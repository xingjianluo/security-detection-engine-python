"""Alert lifecycle, dedupe window boundary and suppression priority tests."""

from __future__ import annotations

import time

import pytest

from detection.errors import AlertTransitionError, RejectReason
from detection.models import AlertStatus, SourceType
from tests.conftest import log_case, write_rules

BRUTE_V1 = {
    "id": "brute", "version": "v1", "revision": 1, "name": "brute",
    "condition": {"field": "event_type", "op": "eq", "value": "login_fail"},
    "severity": "high",
}
BRUTE_V2 = {
    "id": "brute", "version": "v2", "revision": 2, "name": "brute v2",
    "condition": {"field": "event_type", "op": "eq", "value": "login_fail"},
    "severity": "critical", "dedupe_window_seconds": 100,
    "suppress_key": "hostA", "suppress_severity_ceiling": "medium",
}
# v2 rule keyed on a different event type, same suppression key.
OTHER_V2 = {
    "id": "other", "version": "v2", "revision": 1, "name": "other",
    "condition": {"field": "event_type", "op": "eq", "value": "port_scan"},
    "severity": "medium", "dedupe_window_seconds": 100,
    "suppress_key": "hostA", "suppress_severity_ceiling": "medium",
}


def _ev(eid, etype="login_fail", sev="low", ts=None):
    return {"event_id": eid, "type": etype, "severity": sev,
            "ts": ts if ts is not None else time.time()}


def _alerts(service):
    return service.list_alerts()


def test_dedupe_window_boundary_is_deterministic(service, tmp_data_dir, monkeypatch):
    write_rules(tmp_data_dir, [BRUTE_V2])
    service.reload_rules()
    t0 = time.time()
    service.ingest([_ev("a1", ts=t0)], SourceType.JSON, now=t0)
    # last millisecond inside the 100s window -> folded
    service.ingest([_ev("a2", ts=t0 + 50)], SourceType.JSON, now=t0 + 100)
    # one millisecond past boundary -> new alert
    service.ingest([_ev("a3", ts=t0 + 60)], SourceType.JSON, now=t0 + 100.001)

    alerts = _alerts(service)
    counts = sorted(a["event_count"] for a in alerts)
    assert counts == [1, 2], counts
    open_alerts = [a for a in alerts if a["status"] == "open"]
    assert len(open_alerts) == 2
    log_case("window-boundary", "t, t+100, t+100.001", f"counts={counts}")


def test_late_event_inside_open_window_folds(service, tmp_data_dir):
    write_rules(tmp_data_dir, [BRUTE_V2])
    service.reload_rules()
    t0 = time.time()
    service.ingest([_ev("b1", ts=t0 - 10)], SourceType.JSON, now=t0)
    # arrives later but window measured by ingest wall time -> still folds
    service.ingest([_ev("b2", ts=t0 - 5)], SourceType.JSON, now=t0 + 10)
    alerts = _alerts(service)
    assert len(alerts) == 1 and alerts[0]["event_count"] == 2
    log_case("late-fold", "events older than ingest", "single open alert count=2")


def test_suppressed_child_is_distinguishable_and_priority_holds(service, tmp_data_dir):
    write_rules(tmp_data_dir, [BRUTE_V2, OTHER_V2])
    service.reload_rules()
    t0 = time.time()
    # brute opens the suppressor alert (critical, key hostA)
    service.ingest([_ev("s1", etype="login_fail", sev="critical", ts=t0)],
                   SourceType.JSON, now=t0)
    # medium port_scan with same key -> SUPPRESSED child
    service.ingest([_ev("s2", etype="port_scan", sev="medium", ts=t0 + 1)],
                   SourceType.JSON, now=t0 + 1)
    # critical port_scan must NOT be swallowed by the medium ceiling
    service.ingest([_ev("s3", etype="port_scan", sev="critical", ts=t0 + 2)],
                   SourceType.JSON, now=t0 + 2)

    by_id = {a["first_event_id"]: a for a in _alerts(service)}
    assert by_id["s1"]["status"] == AlertStatus.OPEN.value
    assert by_id["s2"]["status"] == AlertStatus.SUPPRESSED.value
    assert by_id["s2"]["parent_alert_id"] == by_id["s1"]["alert_id"]
    assert by_id["s3"]["status"] == AlertStatus.OPEN.value
    assert by_id["s3"]["parent_alert_id"] is None
    log_case("suppression", "critical / medium / critical same key",
             f"s2 suppressed under {by_id['s2']['parent_alert_id']}, s3 open")


def test_lifecycle_transitions(service, tmp_data_dir):
    write_rules(tmp_data_dir, [BRUTE_V2])
    service.reload_rules()
    service.ingest([_ev("t1")], SourceType.JSON, now=time.time())
    alert = _alerts(service)[0]
    aid = alert["alert_id"]

    service.transition_alert(aid, "acknowledged")
    assert service.get_alert(aid)["status"] == "acknowledged"
    service.transition_alert(aid, "resolved")
    assert service.get_alert(aid)["status"] == "resolved"

    with pytest.raises(AlertTransitionError) as ei:
        service.transition_alert(aid, "acknowledged")
    assert ei.value.reason == RejectReason.ILLEGAL_TRANSITION
    log_case("illegal-transition", "resolved -> acknowledged",
             ei.value.reason.value)


def test_merged_alerts_are_distinguishable(service, tmp_data_dir):
    write_rules(tmp_data_dir, [BRUTE_V2, OTHER_V2])
    service.reload_rules()
    t0 = time.time()
    service.ingest([_ev("g1", etype="login_fail", sev="high", ts=t0)],
                   SourceType.JSON, now=t0)
    service.ingest([_ev("g2", etype="port_scan", sev="high", ts=t0 + 1)],
                   SourceType.JSON, now=t0 + 1)
    alerts = _alerts(service)
    parent = next(a for a in alerts if a["first_event_id"] == "g1")
    child = next(a for a in alerts if a["first_event_id"] == "g2")
    merged = service.merge_alerts(parent["alert_id"], child["alert_id"])
    assert merged["status"] == AlertStatus.MERGED.value
    assert merged["parent_alert_id"] == parent["alert_id"]
    # merging again is an illegal transition
    with pytest.raises(AlertTransitionError):
        service.merge_alerts(parent["alert_id"], child["alert_id"])
    log_case("merge", f"{child['alert_id']} -> {parent['alert_id']}", "merged terminal")


def test_historical_alert_keeps_old_rule_binding(service, tmp_data_dir):
    write_rules(tmp_data_dir, [BRUTE_V1])
    service.reload_rules()
    service.ingest([_ev("v1hit")], SourceType.JSON, now=time.time())
    old_alert = _alerts(service)[0]
    assert old_alert["rule_revision"] == 1
    assert old_alert["rule_version"] == "v1"

    write_rules(tmp_data_dir, [BRUTE_V2])
    service.reload_rules()
    service.ingest([_ev("v2hit")], SourceType.JSON)
    new_alert = next(a for a in _alerts(service) if a["first_event_id"] == "v2hit")
    assert new_alert["rule_revision"] == 2
    # historical binding untouched
    again = service.get_alert(old_alert["alert_id"])
    assert again["rule_revision"] == 1 and again["rule_version"] == "v1"
    log_case("rule-evolution", "v1 alert then v2 alert",
             f"old={again['rule_revision']} new={new_alert['rule_revision']}")


def test_cross_window_reuse_starts_fresh_alert_but_keeps_history(service, tmp_data_dir):
    write_rules(tmp_data_dir, [BRUTE_V2])  # window = 100s
    service.reload_rules()
    t0 = time.time()
    for i, dt in enumerate((0, 50, 99.999)):
        service.ingest([_ev(f"w{i}", ts=t0 + dt)], SourceType.JSON, now=t0 + dt)
    # first alert folded 3 events; then cross the boundary
    service.ingest([_ev("w3", ts=t0 + 101)], SourceType.JSON, now=t0 + 101)

    alerts = sorted(_alerts(service), key=lambda a: a["opened_at"])
    assert len(alerts) == 2
    assert alerts[0]["event_count"] == 3
    assert alerts[1]["event_count"] == 1
    # distinct fingerprints across rule revisions remain grouped correctly
    assert alerts[0]["fingerprint"] == alerts[1]["fingerprint"]
    log_case("cross-window", "0/50/99.999 in-window, 101 fresh",
             f"counts=({alerts[0]['event_count']},{alerts[1]['event_count']})")
