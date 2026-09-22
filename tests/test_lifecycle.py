"""告警生命周期：状态机、去重窗口边界、合并归属、抑制优先级、乱序。"""

import logging
from datetime import timedelta

import pytest

from detector.errors import IllegalTransitionError
from detector.models import AlertState, Severity, utcnow
from .helpers import event_payload, log_judgement

log = logging.getLogger("detector.tests")


def _ingest(engine, eid, **over):
    payload = event_payload(eid, **over)
    result = engine.ingest_batch([payload], source="generic_json")
    log_judgement(payload,
                  f"{eid}: {[(a.outcome.value, a.reason, a.dedup_hit) for a in result.accepted]}")
    return result, payload


def test_state_machine_rejects_illegal_transitions(engine):
    _ingest(engine, "s1")
    alert = engine.list_alerts()[0]
    engine.acknowledge(alert.alert_id)
    engine.resolve(alert.alert_id)
    with pytest.raises(IllegalTransitionError) as exc:
        engine.acknowledge(alert.alert_id)
    assert exc.value.reason == "illegal_state_transition"


def test_dedup_window_half_open_boundary(tmp_path):
    """brute 规则 dedup_window_s=300、无抑制；边界为半开区间。"""
    from detector.config import Config
    from detector.engine import Engine
    from detector.models import utcnow

    cfg = Config(rules_dir=tmp_path / "rules", future_tolerance_s=3600)
    engine = Engine(cfg)
    engine.publish_rules_document({"format_version": 2, "revision": 1, "rules": [
        {"id": "brute", "event_type": "login", "severity": "high",
         "dedup_window_s": 300,
         "conditions": {"all": [
             {"field": "src_ip", "op": "prefix", "value": "10."}]},
         "correlation_key": ["src_ip", "user"],
         "merge_key": ["rule_id", "src_ip"]}]})
    now = utcnow()
    _ingest(engine, "w1", timestamp=now.isoformat())
    assert len(engine.list_alerts()) == 1
    _ingest(engine, "w2",
            timestamp=(now + timedelta(seconds=299)).isoformat())
    assert engine.list_alerts()[0].event_count == 2
    _ingest(engine, "w3",
            timestamp=(now + timedelta(seconds=300)).isoformat())
    opens = [a for a in engine.list_alerts() if a.state == AlertState.OPEN]
    assert len(opens) == 2


def test_low_priority_suppressed_high_priority_never(engine):
    now = utcnow()
    _ingest(engine, "p1", timestamp=now.isoformat())
    primary = next(a for a in engine.list_alerts() if a.rule_id == "brute")

    _ingest(engine, "p2", severity="low", src_ip="10.9.9.9", user="x",
            timestamp=(now + timedelta(seconds=10)).isoformat())
    suppressed = [a for a in engine.list_alerts()
                  if a.state == AlertState.SUPPRESSED]
    assert len(suppressed) == 1
    assert suppressed[0].suppressed_by == primary.alert_id
    log.info("抑制归属: %s -> %s",
             suppressed[0].alert_id, suppressed[0].suppressed_by)

    _ingest(engine, "p3", severity="critical", src_ip="10.8.8.8", user="y",
            timestamp=(now + timedelta(seconds=20)).isoformat())
    crit = [a for a in engine.list_alerts() if a.severity == Severity.CRITICAL]
    assert len(crit) == 1 and crit[0].state == AlertState.OPEN

    reopened = engine.suppress_expired_tick(now + timedelta(seconds=100000))
    assert any(a.suppressed_by is None and a.state == AlertState.OPEN
               for a in reopened)


def test_merged_alert_attribution_distinguishable(engine):
    now = utcnow()
    _ingest(engine, "m1", timestamp=now.isoformat())
    parent = engine.list_alerts()[0]
    _ingest(engine, "m2", src_ip="10.7.7.7", user="z",
            timestamp=(now + timedelta(seconds=5)).isoformat())
    child = next(a for a in engine.list_alerts() if a.alert_id != parent.alert_id)
    merged = engine.merge_alert(child.alert_id, parent.alert_id)
    assert merged.state == AlertState.MERGED
    assert merged.merged_into == parent.alert_id
    fetched = engine.get_alert(child.alert_id)
    assert fetched.state == AlertState.MERGED
    with pytest.raises(IllegalTransitionError):
        engine.resolve(child.alert_id)


def test_out_of_order_events_count_once_and_track_extremes(tmp_path):
    from detector.config import Config
    from detector.engine import Engine
    from detector.models import utcnow

    cfg = Config(rules_dir=tmp_path / "rules", future_tolerance_s=3600)
    engine = Engine(cfg)
    engine.publish_rules_document({"format_version": 2, "revision": 1, "rules": [
        {"id": "brute", "event_type": "login", "severity": "high",
         "dedup_window_s": 300,
         "conditions": {"all": [
             {"field": "src_ip", "op": "prefix", "value": "10."}]},
         "correlation_key": ["src_ip", "user"],
         "merge_key": ["rule_id", "src_ip"]}]})
    now = utcnow()
    _ingest(engine, "o2",
            timestamp=(now + timedelta(seconds=100)).isoformat())
    _ingest(engine, "o1", timestamp=now.isoformat())
    alert = engine.list_alerts()[0]
    assert alert.event_count == 2
    assert alert.first_event_id == "o1"
    assert alert.last_event_id == "o2"
