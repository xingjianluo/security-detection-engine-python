"""归档与按需重放：淘汰/归档之后，显式纳入归档的完整重放与当初结论
逐条一致，且可追溯规则版本与输入摘要；归档读失败显式报错；归档过程
不阻塞正常摄入（后台线程）。
"""

import json
import logging
from datetime import timedelta
from pathlib import Path

import pytest

from detector.config import Config
from detector.engine import Engine, replay
from detector.errors import ArchiveError, ReplayConsistencyError
from detector.models import utcnow
from .conftest import BRUTE_RULES
from .helpers import event_payload, log_judgement

log = logging.getLogger("detector.tests")


def _cfg(tmp_path, max_records=14):
    d = tmp_path / "data"
    return Config(
        rules_dir=tmp_path / "rules", data_dir=d,
        journal_path=d / "journal.jsonl", snapshot_path=d / "snapshot.json",
        archive_dir=d / "archive", future_tolerance_s=3600,
        retention_max_records=max_records, retention_max_bytes=10**9,
        retention_policy="evict_oldest", snapshot_every=0)


def _run_pressure(eng, now, n=24):
    kinds = []
    for i in range(n):
        # 制造开告警/折叠/抑制/无命中的混合结论
        if i % 4 == 0:
            payload = event_payload(f"e{i}",
                                    timestamp=(now + timedelta(seconds=i)).isoformat(),
                                    src_ip="10.0.0.1", user="bob")
        elif i % 4 == 1:
            payload = event_payload(f"e{i}", severity="low",
                                    timestamp=(now + timedelta(seconds=i)).isoformat(),
                                    src_ip=f"10.9.{i}.1", user=f"u{i}")
        else:
            payload = event_payload(
                f"e{i}",
                timestamp=(now + timedelta(seconds=i)).isoformat(),
                src_ip="192.168.1.1", user="nomatch")
        r = eng.ingest_batch([payload], source="generic_json")
        log_judgement(payload, r)
        kinds.append(r)
        if eng._archive is not None and eng._archive.pending:
            eng._archive.wait_idle(10)
    if eng._archive is not None:
        eng._archive.wait_idle(10)
    return kinds


def test_archive_replay_matches_original(tmp_path):
    cfg = _cfg(tmp_path)
    eng = Engine(cfg, persist=True)
    eng.publish_rules_document(BRUTE_RULES)
    now = utcnow()
    _run_pressure(eng, now)

    assert eng.store.journal_len() < eng.store.seen_count() * 3  # 已裁剪
    archive_files = list(cfg.archive_dir.glob("seg-*.jsonl"))
    assert archive_files, "淘汰应产生归档分段"

    # 仅当前本地流水的重放只能覆盖仍保留的事件；纳入归档后覆盖全部
    eng_live, report_live = replay(cfg.journal_path, cfg, include_archive=False)
    eng_full, report_full = replay(cfg.journal_path, cfg, include_archive=True)

    assert eng_full.store.seen_count() == eng.store.seen_count()
    assert eng_live.store.seen_count() <= eng_full.store.seen_count()
    assert all(i["consistent"] for i in report_full)

    # 每条判定可追溯输入摘要与命中规则版本
    judged = [i for i in report_full if "original_kind" in i]
    assert len(judged) == eng.store.seen_count()
    for item in judged:
        assert item["input_digest"]
        assert item["original_kind"] in (
            "alert_opened", "alert_suppressed", "alert_dedup",
            "event_no_match")
        if item["original_kind"] in ("alert_opened", "alert_suppressed"):
            assert item["rule_version"] == 2
            assert item["rule_revision"] == 1

    # 重建后的告警终态与逐条结论与实时处理完全一致
    assert sorted(
        (a.alert_id, a.state.value, a.rule_id, a.event_count, a.suppressed_by)
        for a in eng_full.list_alerts()) == sorted(
        (a.alert_id, a.state.value, a.rule_id, a.event_count, a.suppressed_by)
        for a in eng.list_alerts())
    log.info("归档重放一致，事件=%s 分段=%s", len(judged), len(archive_files))


def test_archive_does_not_block_ingestion(tmp_path):
    """归档后台线程不阻塞摄入：摄入返回时业务状态已可用。"""
    import time
    cfg = _cfg(tmp_path, max_records=10)
    eng = Engine(cfg, persist=True)
    eng.publish_rules_document(BRUTE_RULES)
    now = utcnow()
    t0 = time.monotonic()
    evicted_seen = 0
    for i in range(30):
        r = eng.ingest_batch(
            [event_payload(f"e{i}", timestamp=now.isoformat(),
                           src_ip=f"10.1.{i}.1", user=f"u{i}")],
            source="generic_json")
        evicted_seen += r.evicted
        # 摄入后立即一致可见（查询不需要等归档）
        assert eng.store.seen_event(f"e{i}")
    elapsed = time.monotonic() - t0
    assert evicted_seen > 0
    assert elapsed < 10.0  # 远小于串行等待落盘的时间
    eng._archive.wait_idle(10)
    log.info("归档期间摄入耗时=%.3fs 淘汰=%s", elapsed, evicted_seen)


def test_archive_read_failure_raises_explicitly(tmp_path):
    """归档分段缺失/损坏时，显式 ArchiveError，不给静默/半成品结论。"""
    cfg = _cfg(tmp_path)
    eng = Engine(cfg, persist=True)
    eng.publish_rules_document(BRUTE_RULES)
    now = utcnow()
    _run_pressure(eng, now, n=18)

    # 删除 manifest 登记的某个分段
    manifest = json.loads((cfg.archive_dir / "manifest.json").read_text())
    seg = cfg.archive_dir / manifest["segments"][0]["segment"]
    seg.unlink()
    with pytest.raises(ArchiveError) as exc:
        replay(cfg.journal_path, cfg, include_archive=True)
    assert "missing" in str(exc.value)

    # 损坏分段内容
    seg2 = cfg.archive_dir / manifest["segments"][-1]["segment"]
    seg2.write_text("{not valid json\n")
    with pytest.raises(ArchiveError):
        replay(cfg.journal_path, cfg, include_archive=True)


def test_archive_overlap_rejected(tmp_path):
    """归档与本地流水 seq 重叠（异常状态）时重放显式报错，不静默去重。"""
    cfg = _cfg(tmp_path)
    eng = Engine(cfg, persist=True)
    eng.publish_rules_document(BRUTE_RULES)
    now = utcnow()
    _run_pressure(eng, now, n=16)
    # 人为复制一个归档行到 live journal 制造重叠
    writer = eng._archive
    rows = writer.read_archived_rows()
    with open(cfg.journal_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rows[0]) + "\n")
    with pytest.raises(ReplayConsistencyError):
        replay(cfg.journal_path, cfg, include_archive=True)
