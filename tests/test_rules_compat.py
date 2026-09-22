"""Rule version/compatibility tests: old rules keep semantics, unknown
fields/versions are explicitly rejected, reload is atomic."""

from __future__ import annotations

import pytest

from detection.errors import RuleRejectedError, RejectReason
from detection.rules import parse_rule, parse_rules_document
from tests.conftest import log_case

V1 = {
    "id": "r1", "version": "v1", "name": "v1 rule",
    "condition": {"field": "event_type", "op": "eq", "value": "login"},
    "severity": "high",
}


def test_v1_remains_valid_forever():
    rule = parse_rule(V1)
    assert rule.rule_revision == 1
    assert rule.signature
    log_case("v1-baseline", V1, f"sig={rule.signature[:10]}")


@pytest.mark.parametrize("doc,reason", [
    ({**V1, "dedupe_window_seconds": 10}, RejectReason.RULE_SEMANTIC_UNSUPPORTED),
    ({**V1, "suppress_key": "k"}, RejectReason.RULE_SEMANTIC_UNSUPPORTED),
    ({**V1, "condition": {"field": "event_type", "op": "gt", "value": 1}},
     RejectReason.RULE_SEMANTIC_UNSUPPORTED),
    ({**V1, "condition": {"field": "event_type", "op": "regex", "value": ".*"}},
     RejectReason.RULE_SEMANTIC_UNSUPPORTED),
    ({**V1, "unknown_field": 1}, RejectReason.RULE_FIELD_UNSUPPORTED),
    ({**V1, "condition": {"field": "event_type", "op": "eq",
                          "value": "x", "extra": 1}},
     RejectReason.RULE_FIELD_UNSUPPORTED),
    ({**V1, "version": "v0"}, RejectReason.RULE_VERSION_UNSUPPORTED),
    ({**V1, "condition": {"field": "event_type", "op": "eq", "value": "x"},
      "severity": "apocalyptic"}, RejectReason.RULE_SEMANTIC_UNSUPPORTED),
    ({"id": "r9", "version": "v2", "name": "n",
      "condition": {"field": "x", "op": "gt", "value": "notnum"},
      "severity": "low"}, RejectReason.RULE_SEMANTIC_UNSUPPORTED),
    ({"id": "r9", "version": "v2", "name": "n",
      "condition": {"field": "x", "op": "regex", "value": "([unclosed"},
      "severity": "low"}, RejectReason.RULE_SEMANTIC_UNSUPPORTED),
])
def test_rejected_rules(doc, reason):
    with pytest.raises(RuleRejectedError) as ei:
        parse_rule(doc)
    assert ei.value.reason == reason
    log_case("rule-reject", doc, f"reason={ei.value.reason.value}")


def test_v2_features_parse():
    doc = {
        "id": "r2", "version": "v2", "revision": 3, "name": "n",
        "condition": {"field": "fields.count", "op": "gte", "value": 5},
        "severity": "critical", "dedupe_window_seconds": 90,
        "suppress_key": "k", "suppress_severity_ceiling": "medium",
    }
    rule = parse_rule(doc)
    assert rule.rule_revision == 3
    assert rule.dedupe_window_seconds == 90
    assert rule.suppress_severity_ceiling.value == "medium"


def test_duplicate_revision_rejected():
    with pytest.raises(RuleRejectedError) as ei:
        parse_rules_document([V1, V1])
    assert ei.value.reason == RejectReason.RULE_DUPLICATE_ID


def test_bad_file_does_not_change_active_rules(service, cfg, tmp_data_dir):
    from tests.conftest import write_rules
    write_rules(tmp_data_dir, [V1])
    assert service.reload_rules() == ["r1"]
    assert [r["rule_id"] for r in service.list_rules()] == ["r1"]

    write_rules(tmp_data_dir, [
        {"id": "good", "version": "v1", "name": "n",
         "condition": {"field": "event_type", "op": "eq", "value": "x"},
         "severity": "low"},
        {"id": "bad", "version": "v1", "name": "n",
         "condition": {"field": "event_type", "op": "regex", "value": ".*"},
         "severity": "low"},
    ])
    with pytest.raises(RuleRejectedError):
        service.reload_rules()
    # atomic: previous ruleset is still the active one
    assert [r["rule_id"] for r in service.list_rules()] == ["r1"]
    log_case("atomic-reload", "good+bad", "active still r1")
