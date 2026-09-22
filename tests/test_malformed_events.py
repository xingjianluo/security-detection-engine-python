"""畸形事件：错误须被正确归类且原因可区分，失败不污染已有状态。"""

import json
import logging

import pytest

from detector.errors import (
    BatchOverSizeError,
    BatchTooLargeError,
    InvalidTimestampError,
    MissingFieldError,
    UnknownSourceError,
)
from detector.normalize import normalize_event
from detector.models import utcnow
from datetime import timedelta

from .helpers import event_payload, log_judgement

log = logging.getLogger("detector.tests")


def test_missing_required_fields_classified():
    cases = [
        ({}, "missing_field"),
        ({"event_id": "x"}, "missing_field"),
        ({"event_id": "x", "type": "t", "severity": "high"}, "missing_field"),
        ({"event_id": "x", "type": "t", "severity": "bad",
          "timestamp": "2026-01-01T00:00:00Z"}, "invalid_severity"),
        ("not-an-object", "malformed_payload"),
    ]
    for payload, expected_reason in cases:
        with pytest.raises(MissingFieldError) as exc:
            normalize_event(payload, source="generic_json")
        log_judgement(payload, f"拒绝 reason={exc.value.reason}")
        assert exc.value.reason == expected_reason


def test_invalid_timestamps_distinguished():
    for bad in ["not-a-time", "2026-13-40T99:99:99Z", True]:
        payload = {"event_id": "x", "type": "t", "severity": "low",
                   "timestamp": bad}
        with pytest.raises(InvalidTimestampError) as exc:
            normalize_event(payload, source="generic_json")
        log_judgement(payload, f"拒绝 reason={exc.value.reason}")
        assert exc.value.reason == "invalid_timestamp"


def test_unknown_source_distinguished():
    with pytest.raises(UnknownSourceError) as exc:
        normalize_event({"event_id": "x"}, source="kafka-avro-unknown")
    assert exc.value.reason == "unknown_source"


def test_multiple_sources_normalize_to_same_model():
    now = utcnow().isoformat()
    g = normalize_event(event_payload("g", timestamp=now), source="generic_json")
    c = normalize_event({"id": "c", "signatureId": "login", "rt": now,
                         "severity": 8, "src": "10.0.0.1", "suser": "bob"},
                        source="syslog_cef")
    w = normalize_event({"uuid": "w", "alert_type": "login", "level": 4,
                         "created_at": now, "source_ip": "10.0.0.1",
                         "account": "bob"}, source="alert_webhook")
    for ev in (g, c, w):
        log_judgement(ev.raw, f"接受 event_id={ev.event_id} severity={ev.severity.value}")
        assert ev.event_type == "login"
        assert ev.src_ip == "10.0.0.1"
        assert ev.user == "bob"
        assert ev.digest


def test_batch_limits_reject_entire_batch(engine):
    now = utcnow().isoformat()
    too_many = [event_payload(f"x{i}", timestamp=now)
                for i in range(engine.config.max_batch_size + 1)]
    with pytest.raises(BatchTooLargeError) as exc:
        engine.ingest_batch(too_many, source="generic_json")
    assert exc.value.reason == "batch_too_large"
    assert engine.stats()["events"] == 0  # 无部分写入

    huge = [event_payload("big", timestamp=now, raw_extra="x" * 70000)]
    with pytest.raises(BatchOverSizeError) as exc:
        engine.ingest_batch(huge, source="generic_json")
    assert exc.value.reason == "event_oversize_bytes"
    assert engine.stats()["events"] == 0


def test_single_bad_event_does_not_pollute(engine):
    before = engine.stats()
    good = event_payload("good-1")
    result = engine.ingest_batch([good, {"bad": True}], source="generic_json")
    log_judgement(good, f"accepted={result.accepted}")
    assert len(result.accepted) == 1
    assert len(result.rejected) == 1
    assert result.rejected[0].reason == "missing_field"
    assert engine.stats()["events"] == before["events"] + 1


def test_stale_and_future_events_rejected(engine):
    old = event_payload(
        "old-1",
        timestamp=(utcnow() - timedelta(
            seconds=engine.config.max_out_of_order_s + 100)).isoformat())
    r = engine.ingest_batch([old], source="generic_json")
    assert r.accepted[0].reason == "stale_event"
    assert engine.get_event("old-1") is None

    future = event_payload(
        "future-1",
        timestamp=(utcnow() + timedelta(
            seconds=engine.config.future_tolerance_s + 100)).isoformat())
    r = engine.ingest_batch([future], source="generic_json")
    assert r.accepted[0].reason == "future_timestamp"
    assert engine.get_event("future-1") is None
