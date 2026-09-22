"""Replay reproducibility and rule-version traceability tests."""

from __future__ import annotations

import time

from detection.models import SourceType
from tests.conftest import log_case, write_rules

V1 = {
    "id": "brute", "version": "v1", "revision": 1, "name": "brute",
    "condition": {"field": "event_type", "op": "eq", "value": "login_fail"},
    "severity": "high",
}
V2 = {
    "id": "brute", "version": "v2", "revision": 2, "name": "brute",
    "condition": {"field": "event_type", "op": "eq", "value": "login_fail"},
    "severity": "critical", "dedupe_window_seconds": 3600,
    "suppress_key": "hostA", "suppress_severity_ceiling": "medium",
}


def _ev(eid, etype="login_fail", sev="high"):
    return {"event_id": eid, "type": etype, "severity": sev, "ts": time.time()}


def test_replay_matches_original_and_pins_rule_revision(service, tmp_data_dir):
    write_rules(tmp_data_dir, [V1])
    service.reload_rules()
    service.ingest([_ev("h1"), _ev("h2")], SourceType.JSON)

    # evolve the rule; the old conclusions stay bound to revision 1
    write_rules(tmp_data_dir, [V2])
    service.reload_rules()
    service.ingest([_ev("h3")], SourceType.JSON)

    old_alerts = {a["first_event_id"]: a for a in service.list_alerts()}
    assert old_alerts["h1"]["rule_revision"] == 1
    assert old_alerts["h3"]["rule_revision"] == 2

    report = service.replay()
    assert report["consistent"] is True, report["mismatches"]
    assert report["events_replayed"] == 3
    # every decision traces event input digest + exact rule revision/signature
    for d in report["decisions"]:
        assert d["input_digest"] and d["rule_signature"]
    sigs = {(d["event_id"], d["rule_revision"]) for d in report["decisions"]}
    assert ("h1", 1) in sigs and ("h3", 2) in sigs
    log_case("replay-versioned", "v1 events then v2 event",
             f"consistent={report['consistent']} decisions={report['decisions_replayed']}")


def test_replay_with_empty_rules_is_stable(service, tmp_data_dir):
    service.ingest([_ev("n1")], SourceType.JSON)
    report = service.replay()
    assert report["consistent"] is True
    assert report["decisions_original"] == 0
    log_case("replay-no-rules", "1 event, 0 rules", "0 decisions both sides")


def test_decisions_record_match_and_miss_with_basis(service, tmp_data_dir):
    write_rules(tmp_data_dir, [V1])
    service.reload_rules()
    service.ingest([_ev("m1", etype="login_fail"), _ev("m2", etype="other")],
                   SourceType.JSON)
    decisions = service.journal.all()
    assert len(decisions) == 2
    matched = {d.event_id: d for d in decisions}
    assert matched["m1"].matched is True and matched["m1"].alert_id
    assert matched["m2"].matched is False and matched["m2"].alert_id is None
    assert "failed" in matched["m2"].reason
    log_case("decision-basis", "one hit one miss",
             f"m1={matched['m1'].reason} | m2={matched['m2'].reason}")


def test_snapshot_file_is_written(service, tmp_data_dir):
    service.ingest([_ev("s1")], SourceType.JSON)
    path = service.save_snapshot()
    import json
    with open(path) as handle:
        payload = json.load(handle)
    assert payload["events"][0]["event_id"] == "s1"
    log_case("snapshot", "1 event", path)


def test_file_journal_persists_decisions_with_rule_binding(service, tmp_data_dir):
    from detection.journal import PersistentJournal
    import os
    write_rules(tmp_data_dir, [V1])
    service.reload_rules()
    service.ingest([_ev("d1")], SourceType.JSON)

    path = os.path.join(tmp_data_dir, "journal.log")
    rows = PersistentJournal(path).read_all()
    assert rows and all(r.rule_signature and r.input_digest for r in rows)
    hit = next(r for r in rows if r.matched)
    assert hit.rule_id == "brute" and hit.rule_revision == 1 and hit.alert_id
    log_case("file-journal", "1 event / 1 rule", f"rows={len(rows)} hit={hit.alert_id}")
