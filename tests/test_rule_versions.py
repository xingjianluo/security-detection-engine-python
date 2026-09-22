"""规则版本差异：旧格式语义保持、未支持字段拒绝、历史结论不可改写。"""

import logging

import pytest

from detector.errors import (
    RuleValidationError,
    UnsupportedRuleFieldError,
    UnsupportedRuleSemanticsError,
    UnsupportedRuleVersionError,
)
from detector.rules import load_rule_document

log = logging.getLogger("detector.tests")


def test_v1_rule_keeps_original_semantics():
    doc = {"format_version": 1, "revision": 5, "rules": [
        {"id": "old", "event_type": "ssh_fail",
         "min_severity": "medium", "window_seconds": 120}]}
    rules, rev = load_rule_document(doc)
    assert rev == 5
    r = rules[0]
    assert r.version == 1 and r.dedup_window_s == 120
    # min_severity -> 严重度基线 + gte 条件，语义保持
    assert r.severity.value == "medium"
    assert r.conditions["all"][0]["field"] == "severity"
    log.info("v1 规则兼容: id=%s window=%s conditions=%s",
             r.rule_id, r.dedup_window_s, r.conditions)


def test_unsupported_version_rejected():
    with pytest.raises(UnsupportedRuleVersionError) as exc:
        load_rule_document({"format_version": 99, "rules":
                            [{"id": "x", "event_type": "t"}]})
    assert exc.value.reason == "unsupported_rule_version"


def test_unknown_fields_never_silently_ignored():
    cases = [
        ({"format_version": 2, "rules": [
            {"id": "x", "event_type": "t", "ai_threshold": 0.9}]},
         UnsupportedRuleFieldError),
        ({"format_version": 2, "rules": [
            {"id": "x", "event_type": "t",
             "conditions": {"all": [
                 {"field": "src_ip", "op": "near", "value": "x"}]}}]},
         UnsupportedRuleSemanticsError),
        ({"format_version": 2, "rules": [
            {"id": "x", "event_type": "t",
             "conditions": {"all": [
                 {"field": "process_hash", "op": "eq", "value": "x"}]}}]},
         UnsupportedRuleFieldError),
        ({"format_version": 2, "rules": [
            {"id": "x", "event_type": "t"}], "comment": "hi"},
         UnsupportedRuleFieldError),
    ]
    for doc, expected in cases:
        with pytest.raises(expected) as exc:
            load_rule_document(doc)
        log.info("拒绝非法规则: reason=%s detail=%s", exc.value.reason, exc.value)


def test_history_alert_binds_rule_revision(engine):
    from datetime import timedelta
    from detector.models import utcnow
    from .helpers import event_payload

    # revision 1 下产生告警
    r = engine.ingest_batch(
        [event_payload("h1", timestamp=utcnow().isoformat())],
        source="generic_json")
    assert r.accepted[0].outcome.value == "accepted"
    old = next(a for a in engine.list_alerts() if a.rule_id == "brute")
    assert old.rule_revision == 1 and old.rule_version == 2

    # 发布 revision 2（不同条件）
    engine.publish_rules_document({"format_version": 2, "revision": 2, "rules": [
        {"id": "brute", "event_type": "login", "severity": "critical",
         "conditions": {"all": [
             {"field": "user", "op": "eq", "value": "admin"}]}}]})

    later = event_payload(
        "h2", user="admin", severity="critical",
        timestamp=(utcnow() + timedelta(seconds=10)).isoformat())
    engine.ingest_batch([later], source="generic_json")

    # 旧告警结论保持 revision 1
    again = engine.get_alert(old.alert_id)
    assert again.rule_revision == 1
    # 历史 revision 规则仍可取出复现
    assert engine.store.rules_at(1)[0].rule_id == "brute"
    assert engine.store.rules_at(2)[0].severity.value == "critical"
    log.info("历史告警 id=%s 绑定 v=%s rev=%s 未被改写",
             old.alert_id, again.rule_version, again.rule_revision)


def test_revision_must_advance(engine):
    with pytest.raises(RuleValidationError):
        engine.publish_rules_document({"format_version": 2, "revision": 1,
                                       "rules": [{"id": "x",
                                                  "event_type": "login",
                                                  "severity": "low"}]})
