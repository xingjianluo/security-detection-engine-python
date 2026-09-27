"""有界保留：reject_new 与 evict_oldest 两条路径可从返回中区分；
淘汰只移除历史明细，活动告警（去重/抑制锚点）与幂等锚点保持一致。
"""

import logging
from pathlib import Path

import pytest

from detector.config import Config
from detector.engine import Engine
from detector.errors import (
    ArchiveBackpressureError,
    RetentionFullError,
)
from detector.models import utcnow
from .conftest import BRUTE_RULES
from .helpers import event_payload, log_judgement

log = logging.getLogger("detector.tests")


def _cfg(tmp_path: Path, *, policy: str, max_records: int,
         archive: bool = True, max_pending: int = 8) -> Config:
    d = tmp_path / "data"
    return Config(
        rules_dir=tmp_path / "rules", data_dir=d,
        journal_path=d / "journal.jsonl", snapshot_path=d / "snapshot.json",
        archive_dir=d / "archive", future_tolerance_s=3600,
        retention_max_records=max_records, retention_max_bytes=10**9,
        retention_policy=policy, archive_enabled=archive,
        archive_max_pending=max_pending, snapshot_every=0)


def _event(i, now, **over):
    return event_payload(f"e{i}", timestamp=now.isoformat(), **over)


def test_reject_new_path(tmp_path):
    """容量到上限：新进入被显式拒绝，原因码 retention_full，整批零写入。"""
    cfg = _cfg(tmp_path, policy="reject_new", max_records=12)
    eng = Engine(cfg, persist=True)
    eng.publish_rules_document(BRUTE_RULES)
    now = utcnow()
    accepted_ids = set()
    for i in range(4):
        r = eng.ingest_batch([_event(i, now, src_ip="10.0.0.1", user="bob")],
                             source="generic_json")
        accepted_ids.add(f"e{i}")
        assert r.evicted == 0
    # 继续投递 -> 容量满，整批拒绝（事务性，无部分写入）
    with pytest.raises(RetentionFullError) as exc:
        eng.ingest_batch([_event(99, now, src_ip="10.0.0.1", user="bob")],
                         source="generic_json")
    assert exc.value.reason == "retention_full"
    assert "retention full" in str(exc.value)
    assert eng.get_event("e99") is None
    assert eng.stats()["events"] == 4
    # 与淘汰路径的返回区分：此前所有批次 evicted=0；拒绝是异常而非逐条结果
    log.info("reject_new 拒绝原因=%s", exc.value.reason)


def test_evict_oldest_path_and_distinguishable_result(tmp_path):
    """容量到上限：淘汰最旧明细，返回里 evicted>0 且容量水位回落。"""
    cfg = _cfg(tmp_path, policy="evict_oldest", max_records=12)
    eng = Engine(cfg, persist=True)
    eng.publish_rules_document(BRUTE_RULES)
    now = utcnow()
    saw_eviction = False
    for i in range(20):
        r = eng.ingest_batch(
            [_event(i, now, src_ip=f"10.0.{i}.1", user=f"u{i}")],
            source="generic_json")
        log_judgement(_event(i, now), r)
        if r.evicted:
            saw_eviction = True
            # 淘汰结果可与拒绝区分：正常返回 + evicted>0 + 原因非异常
            assert r.evicted > 0
            assert r.retained_records <= cfg.retention_max_records
    assert saw_eviction
    eng._archive.wait_idle(10)
    # 占用有界：始终不超过上限（略宽的条数以容纳一次摄入新增）
    assert eng.store.retained_count() <= cfg.retention_max_records + 3
    # 幂等锚点不丢：全部 20 个 event_id 仍判为已处理
    assert eng.store.seen_count() == 20


def test_eviction_keeps_dedup_and_suppression_anchors(tmp_path):
    """淘汰大量历史后：重复投递仍判重；活动告警去重/抑制锚点不漂移。"""
    cfg = _cfg(tmp_path, policy="evict_oldest", max_records=15)
    eng = Engine(cfg, persist=True)
    eng.publish_rules_document(BRUTE_RULES)
    now = utcnow()

    # 建立一个高优先级活动告警（抑制者）与折叠计数
    for i in range(2):
        eng.ingest_batch(
            [event_payload(f"h{i}", timestamp=now.isoformat(),
                           src_ip="10.0.0.1", user="bob")],
            source="generic_json")
    suppressor_id = [
        a for a in eng.list_alerts() if a.rule_id == "brute"][0].alert_id

    # 大量独立低/高优事件把历史明细挤出保留窗口
    for i in range(30):
        eng.ingest_batch(
            [event_payload(f"x{i}", timestamp=now.isoformat(),
                           severity="low", src_ip=f"10.2.{i}.1",
                           user=f"v{i}")], source="generic_json")
        if eng._archive.pending:
            eng._archive.wait_idle(10)
    eng._archive.wait_idle(10)

    # 最旧的 h0 明细早已被淘汰，但重复投递仍判已处理（锚点保留）
    r = eng.ingest_batch(
        [event_payload("h0", timestamp=now.isoformat(),
                       src_ip="10.0.0.1", user="bob")],
        source="generic_json")
    assert r.accepted[0].dedup_hit is True

    # 抑制者仍处于活动状态、trace 锚点完好：窗口内新的低优候选仍被抑制
    suppressor = eng.get_alert(suppressor_id)
    assert suppressor.state.value == "open"
    assert suppressor.trace.get("suppress_window_s") == 600
    eng.ingest_batch(
        [event_payload("fresh_low", timestamp=now.isoformat(),
                       severity="low", src_ip="10.4.4.4", user="w")],
        source="generic_json")
    cand = [a for a in eng.list_alerts() if a.last_event_id == "fresh_low"]
    assert cand and cand[0].state.value == "suppressed"
    assert cand[0].suppressed_by == suppressor_id


def test_evict_oldest_without_archive_trims_inline(tmp_path):
    """archive_enabled=False 时淘汰直接移除明细与流水（不留本地归档）。"""
    cfg = _cfg(tmp_path, policy="evict_oldest", max_records=10,
               archive=False)
    eng = Engine(cfg, persist=True)
    eng.publish_rules_document(BRUTE_RULES)
    now = utcnow()
    for i in range(15):
        eng.ingest_batch(
            [_event(i, now, src_ip=f"10.1.{i}.1", user=f"u{i}")],
            source="generic_json")
    assert eng.store.retained_count() <= cfg.retention_max_records + 3
    assert not cfg.archive_dir.exists() or not list(
        (cfg.archive_dir).glob("seg-*.jsonl"))
