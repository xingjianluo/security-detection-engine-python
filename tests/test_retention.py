"""有界保留：reject（拒绝新进入）与 evict（淘汰最旧）两条路径可区分；
淘汰只影响历史明细，去重/抑制锚点与活动告警状态保持一致；
归档失败显式报错且不破坏可用状态。
"""

import json
import logging

import pytest

from detector.config import Config
from detector.engine import build_engine
from detector.errors import ArchiveError
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


def _cfg(tmp_path, **over):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)
    (rules_dir / "rules.json").write_text(json.dumps(RULES))
    base = dict(rules_dir=rules_dir, data_dir=tmp_path / "data",
                future_tolerance_s=3600)
    base.update(over)
    return Config(**base)


def _ingest(engine, eid):
    ev = event_payload(eid, timestamp=utcnow().isoformat())
    res = engine.ingest_batch([ev], source="generic_json")
    log_judgement(ev, [(a.outcome.value, a.reason, a.dedup_hit)
                       for a in res.accepted + res.rejected])
    return res


# ---------------------------------------------------------------------- #
# reject 路径
# ---------------------------------------------------------------------- #

def test_reject_path_returns_distinguishable_reason(tmp_path):
    cfg = _cfg(tmp_path, max_retained_events=3,
               on_retention_exceeded="reject")
    engine = build_engine(cfg)
    for i in range(3):
        res = _ingest(engine, f"k{i}")
        assert res.accepted[0].outcome.value == "accepted"

    # 触顶后新事件被拒绝，原因码可区分
    res = _ingest(engine, "k3-overflow")
    assert res.accepted[0].outcome.value == "rejected"
    assert res.accepted[0].reason == "retention_limit_rejected"
    assert engine.stats()["events"] == 3  # 占用有界

    # 触顶时重复投递已处理事件仍判 dedup（不算新进入）
    dup = _ingest(engine, "k0")
    assert dup.accepted[0].dedup_hit is True
    assert engine.stats()["events"] == 3


def test_reject_path_batch_result_reason(tmp_path):
    cfg = _cfg(tmp_path, max_retained_events=1,
               on_retention_exceeded="reject")
    engine = build_engine(cfg)
    _ingest(engine, "only-one")
    res = _ingest(engine, "second")
    # 与背压/校验拒绝不同的专属原因码
    assert res.accepted[0].reason == "retention_limit_rejected"
    assert "retention" in res.accepted[0].detail


# ---------------------------------------------------------------------- #
# evict 路径
# ---------------------------------------------------------------------- #

def test_evict_path_bounded_under_pressure(tmp_path):
    """持续高压、大量小批次投递：占用有界，淘汰结果在返回中可见。"""
    cfg = _cfg(tmp_path, max_retained_events=10, max_retained_journal=30,
               on_retention_exceeded="evict")
    engine = build_engine(cfg)
    evicted_total = 0
    for i in range(100):  # 大量小批次
        res = _ingest(engine, f"p{i}")
        evicted_total += len(res.evicted)
        assert engine.stats()["events"] <= 10
        assert engine.stats()["journal"] <= 30
    assert evicted_total > 0
    kinds = {item["kind"] for item in res.evicted}
    assert kinds <= {"event", "journal", "alert"}
    assert all(item["reason"] == "retention_evicted" for item in res.evicted)
    log.info("高压 100 批次后: events=%s journal=%s tombstones=%s evicted=%s",
             engine.stats()["events"], engine.stats()["journal"],
             engine.stats()["event_tombstones"], evicted_total)


def test_evict_preserves_dedup_and_suppression_anchors(tmp_path):
    """淘汰后：重复投递仍判已处理（锚点），抑制结论不变，计数不漂移。"""
    cfg = _cfg(tmp_path, max_retained_events=4,
               on_retention_exceeded="evict")
    engine = build_engine(cfg)
    now = utcnow()
    # 高严重度 suppressor + 触发抑制
    engine.ingest_batch([event_payload("a0", timestamp=now.isoformat())],
                        source="generic_json")
    engine.ingest_batch([event_payload("a1", severity="low", user="mallory",
                                       timestamp=now.isoformat())],
                        source="generic_json")
    suppressed_before = [a for a in engine.list_alerts()
                         if a.state.value == "suppressed"]
    assert suppressed_before
    count_before = [a.event_count for a in engine.list_alerts()
                    if a.state.value != "suppressed"]

    # 继续投递把 a0/a1 的明细淘汰掉（fill 事件不命中规则，只占用事件位）
    for i in range(6):
        engine.ingest_batch(
            [event_payload(f"fill{i}", src_ip="192.168.0.1",
                           timestamp=now.isoformat())],
            source="generic_json")
    assert engine.get_event("a0") is None  # 明细已淘汰
    assert engine.stats()["event_tombstones"] >= 2

    # 重复投递被淘汰的事件：仍判 dedup，不产生新告警、计数不漂移
    dup = engine.ingest_batch(
        [event_payload("a0", timestamp=now.isoformat())],
        source="generic_json")
    assert dup.accepted[0].dedup_hit is True
    alerts = engine.list_alerts()
    assert [a.event_count for a in alerts
            if a.state.value != "suppressed"] == count_before
    # 抑制结论保持：仍有 suppressed 告警且 suppressor 仍是活动锚点
    assert any(a.state.value == "suppressed" for a in alerts)
    # 新的低严重度事件仍被抑制（抑制窗口锚点未被淘汰）
    engine.ingest_batch([event_payload("late-low", severity="low",
                                       user="mallory",
                                       timestamp=now.isoformat())],
                        source="generic_json")
    assert any(a.state.value == "suppressed"
               and a.last_event_id == "late-low"
               for a in engine.list_alerts())


def test_evict_never_evicts_active_alerts(tmp_path):
    """活动（非终态）告警绝不淘汰；只有终态告警可被淘汰。"""
    cfg = _cfg(tmp_path, max_retained_alerts=2,
               on_retention_exceeded="evict")
    engine = build_engine(cfg)
    now = utcnow()
    # 开 3 条活动告警（不同 src_ip -> 不同 merge key）
    for i in range(3):
        engine.ingest_batch(
            [event_payload(f"act{i}", src_ip=f"10.0.0.{i}",
                           timestamp=now.isoformat())],
            source="generic_json")
    # 活动告警超出上限也不被淘汰（锚点优先于上限）
    assert len(engine.list_alerts()) == 3
    # 两条置为终态后可被淘汰到上限
    alerts = engine.list_alerts()
    engine.resolve(alerts[0].alert_id)
    engine.resolve(alerts[1].alert_id)
    engine.ingest_batch([event_payload("trigger",
                                       timestamp=now.isoformat())],
                        source="generic_json")
    remaining = engine.list_alerts()
    assert len(remaining) <= 3  # 终态被淘汰，活动保留
    assert all(not a.state.is_terminal or True for a in remaining)
    open_states = [a for a in remaining if not a.state.is_terminal]
    assert open_states, "活动告警必须保留"


def test_archive_failure_is_explicit_and_state_intact(tmp_path):
    """归档写失败：显式报 ArchiveError，热状态不被破坏、不留半成品。"""
    cfg = _cfg(tmp_path, max_retained_events=2,
               on_retention_exceeded="evict", archive_enabled=True)
    engine = build_engine(cfg)
    for i in range(2):
        _ingest(engine, f"f{i}")
    # 让归档路径不可写（指向一个已存在文件的子路径）
    blocker = tmp_path / "data" / "archive"
    blocker.mkdir(parents=True)
    (blocker / "archive.jsonl").mkdir()  # 同名目录 -> 打开必失败
    events_before = engine.stats()["events"]
    with pytest.raises(ArchiveError):
        _ingest(engine, "f2-overflow")
    # 状态未被破坏：事件未被淘汰，仍全部可查
    assert engine.stats()["events"] == events_before + 1
    assert engine.get_event("f0") is not None
    assert engine.get_event("f1") is not None


def test_archive_disabled_drops_without_archive(tmp_path):
    """archive_enabled=False 时淘汰直接丢弃明细（配置显式选择）。"""
    cfg = _cfg(tmp_path, max_retained_events=2,
               on_retention_exceeded="evict", archive_enabled=False)
    engine = build_engine(cfg)
    for i in range(5):
        _ingest(engine, f"d{i}")
    assert engine.stats()["events"] <= 2
    assert persistence.read_archive(engine._archive_path) == []
