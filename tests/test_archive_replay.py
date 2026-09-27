"""归档与按需重放：被淘汰的历史落入本地归档；日常查询不加载归档；
显式 include_archive 的完整重放结论与无归档时一致，且每条判定可追溯到
规则版本与输入摘要；归档损坏显式报错。
"""

import json
import logging

import pytest

from detector.config import Config
from detector.engine import build_engine, replay
from detector.errors import ArchiveError, ReplayConsistencyError
from detector.models import utcnow
from detector import persistence
from .helpers import event_payload, log_judgement

log = logging.getLogger("detector.tests")

RULES = {
    "format_version": 2, "revision": 1, "rules": [
        {"id": "brute", "event_type": "login", "severity": "high",
         "conditions": {"all": [
             {"field": "src_ip", "op": "prefix", "value": "10."}]},
         "correlation_key": ["src_ip", "user"],
         "merge_key": ["rule_id", "src_ip"],
         "suppress": {"window_s": 600, "max_severity": "medium"}},
        {"id": "probe", "event_type": "login", "severity": "low",
         "conditions": {"all": [
             {"field": "src_ip", "op": "prefix", "value": "10."}]},
         "correlation_key": ["src_ip", "user"],
         "merge_key": ["rule_id", "src_ip"]},
    ],
}


@pytest.fixture
def cfg(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rules.json").write_text(json.dumps(RULES))
    return Config(rules_dir=rules_dir, data_dir=tmp_path / "data",
                  future_tolerance_s=3600)


def _feed(engine, count, prefix="e"):
    now = utcnow()
    for i in range(count):
        # 高低严重度交替，覆盖 opened/dedup/suppressed 多种结论
        sev = "high" if i % 3 else "low"
        user = "bob" if i % 2 else "mallory"
        ev = event_payload(f"{prefix}{i}", severity=sev, user=user,
                           timestamp=now.isoformat())
        res = engine.ingest_batch([ev], source="generic_json")
        log_judgement(ev, [(a.outcome.value, a.dedup_hit) for a in res.accepted])


def test_evicted_history_goes_to_archive_with_clear_boundary(cfg):
    """淘汰的事件/告警/流水都落入归档；日常查询不加载归档。"""
    cfg = Config(**{**cfg.__dict__, "max_retained_events": 5,
                    "max_retained_journal": 15,
                    "on_retention_exceeded": "evict"})
    engine = build_engine(cfg)
    _feed(engine, 20)

    archive_path = cfg.archive_dir / "archive.jsonl"
    assert archive_path.exists()
    records = persistence.read_archive(archive_path)
    kinds = {r["record_kind"] for r in records}
    assert "event" in kinds and "journal" in kinds
    # 边界清楚：每条归档记录带归档时间与类别；热存储只剩上限内明细
    assert all(r["archived_at"] and r["data"] for r in records)
    assert engine.stats()["events"] <= 5
    # 日常查询不加载归档：被淘汰的事件查不到，但重复投递仍判已处理
    assert engine.get_event("e0") is None
    dup = engine.ingest_batch(
        [event_payload("e0", severity="low", user="mallory",
                       timestamp=utcnow().isoformat())],
        source="generic_json")
    assert dup.accepted[0].dedup_hit is True


def test_replay_with_archive_matches_no_archive_baseline(cfg):
    """完整重放（显式纳入归档）的结论与无淘汰基线逐条一致。"""
    # 基线：不限制保留，全量流水重放
    baseline_engine = build_engine(cfg)
    _feed(baseline_engine, 15)
    baseline_eng, baseline_report = replay(cfg.journal_path, cfg)
    baseline_outcomes = {
        i["event_id"]: (i["original_kind"], i.get("rule_id"),
                        i.get("rule_version"), i.get("rule_revision"))
        for i in baseline_report if i["kind"] == "event_accepted"}

    # 另一目录：小保留上限触发淘汰+归档，再带归档重放
    import tempfile
    from pathlib import Path
    tmp2 = Path(tempfile.mkdtemp())
    rules2 = tmp2 / "rules"
    rules2.mkdir()
    (rules2 / "rules.json").write_text(json.dumps(RULES))
    cfg2 = Config(rules_dir=rules2, data_dir=tmp2 / "data",
                  future_tolerance_s=3600,
                  max_retained_events=4, max_retained_journal=8,
                  on_retention_exceeded="evict")
    engine2 = build_engine(cfg2)
    _feed(engine2, 15)
    assert (cfg2.archive_dir / "archive.jsonl").exists()

    # 不带归档：流水被截断，重放显式失败而不是给错误结论
    with pytest.raises(ReplayConsistencyError):
        replay(cfg2.journal_path, cfg2)

    # 带归档：逐条结论与基线一致
    archived_eng, report = replay(cfg2.journal_path, cfg2,
                                  include_archive=True)
    outcomes = {
        i["event_id"]: (i["original_kind"], i.get("rule_id"),
                        i.get("rule_version"), i.get("rule_revision"))
        for i in report if i["kind"] == "event_accepted"}
    assert outcomes == baseline_outcomes
    # 每条判定仍可追溯输入摘要与规则版本
    for item in report:
        assert item["consistent"] is True
        if item["kind"] == "event_accepted":
            assert item["input_digest"]
            if item["original_kind"] in ("alert_opened", "alert_suppressed"):
                assert item["rule_revision"] == 1
    # 重建状态与基线一致
    assert archived_eng.stats()["events"] == baseline_eng.stats()["events"]
    assert sorted((a.alert_id, a.state.value, a.event_count)
                  for a in archived_eng.list_alerts()) == \
           sorted((a.alert_id, a.state.value, a.event_count)
                  for a in baseline_eng.list_alerts())
    log.info("带归档重放 %d 条事件结论与基线一致", len(outcomes))


def test_corrupt_archive_fails_explicitly(cfg, tmp_path):
    """归档损坏：读取显式报 ArchiveError，不给静默结论。"""
    cfg = Config(**{**cfg.__dict__, "max_retained_events": 2,
                    "on_retention_exceeded": "evict"})
    engine = build_engine(cfg)
    _feed(engine, 6)
    archive_path = cfg.archive_dir / "archive.jsonl"
    assert archive_path.exists()
    # 写入半行损坏数据
    with open(archive_path, "a", encoding="utf-8") as fh:
        fh.write('{"record_kind": "journal", "data": {broken\n')
    with pytest.raises(ArchiveError):
        persistence.read_archive(archive_path)
    with pytest.raises(ArchiveError):
        replay(cfg.journal_path, cfg, include_archive=True)
    # 当前可用状态未被破坏，摄入继续工作
    assert engine.stats()["events"] == 2
    res = engine.ingest_batch(
        [event_payload("still-ok", timestamp=utcnow().isoformat())],
        source="generic_json")
    assert res.accepted[0].outcome.value == "accepted"
    log.info("损坏归档后引擎状态: %s", engine.stats()["events"])
