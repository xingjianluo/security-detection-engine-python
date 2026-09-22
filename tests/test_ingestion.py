"""Malformed-event tests: rejection reasons must be distinct, failures must
not pollute existing state, and retries must be idempotent."""

from __future__ import annotations

import time

import pytest

from detection.config import EngineConfig
from detection.errors import EventRejectedError, RejectReason
from detection.ingestion import ingest_batch
from detection.models import Severity, SourceType
from detection.store import EventStore
from tests.conftest import log_case


def _ev(event_id="e1", **overrides):
    base = {"event_id": event_id, "type": "login", "severity": "high",
            "ts": time.time()}
    base.update(overrides)
    return base


def test_retry_and_concurrent_duplicate_idempotent(cfg):
    store = EventStore(capacity=100)
    now = time.time()
    r1 = ingest_batch([_ev()], SourceType.JSON, store, now=now, cfg=cfg)
    assert r1.accepted_count == 1
    log_case("retry-1", _ev(), f"accepted={r1.accepted_count}")

    r2 = ingest_batch([_ev()], SourceType.JSON, store, now=now + 1, cfg=cfg)
    assert r2.accepted_count == 0
    assert r2.duplicate_ids == ["e1"]
    assert store.count() == 1
    log_case("retry-2", _ev(), f"duplicates={r2.duplicate_ids}")


def test_within_batch_duplicate_collapses(cfg):
    store = EventStore(capacity=100)
    now = time.time()
    r = ingest_batch([_ev(), _ev(event_id="e2"), _ev()],
                     SourceType.JSON, store, now=now, cfg=cfg)
    assert r.accepted_count == 2
    assert r.duplicate_ids == ["e1"]
    log_case("batch-dup", ["e1", "e2", "e1"], f"accepted={r.accepted_count}")


def test_rejection_reasons_are_distinguishable(cfg):
    store = EventStore(capacity=100)
    now = time.time()
    cases = [
        (_ev(event_id="m1", type=None), RejectReason.MISSING_FIELD),
        (_ev(event_id="m2", severity=""), RejectReason.MISSING_FIELD),
        (_ev(event_id="m3", ts="yesterday-ish"), RejectReason.BAD_TIMESTAMP),
        (_ev(event_id="m4", ts=now + 3600), RejectReason.BAD_TIMESTAMP),
        ("not-a-dict", RejectReason.MALFORMED_PAYLOAD),
        (_ev(event_id="m5", ts=now - cfg.late_event_horizon_seconds - 10),
         RejectReason.STALE_EVENT),
    ]
    for payload, expected in cases:
        r = ingest_batch([payload], SourceType.JSON, store, now=now, cfg=cfg)
        assert len(r.rejected) == 1, payload
        assert r.rejected[0].reason == expected.value, (payload, r.rejected)
        log_case("reject", payload, f"reason={r.rejected[0].reason}")
    assert store.count() == 0  # nothing rejected got persisted


def test_batch_level_rejections_leave_state_untouched(cfg):
    store = EventStore(capacity=100)
    now = time.time()
    ingest_batch([_ev(event_id="seed")], SourceType.JSON, store, now=now, cfg=cfg)

    with pytest.raises(EventRejectedError) as ei:
        ingest_batch([], SourceType.JSON, store, now=now, cfg=cfg)
    assert ei.value.reason == RejectReason.BATCH_EMPTY

    small_cfg = EngineConfig(data_dir=cfg.data_dir, max_batch_events=2)
    with pytest.raises(EventRejectedError) as ei:
        ingest_batch([_ev("a"), _ev("b"), _ev("c")], SourceType.JSON,
                     store, now=now, cfg=small_cfg)
    assert ei.value.reason == RejectReason.BATCH_TOO_LARGE

    with pytest.raises(EventRejectedError) as ei:
        ingest_batch(["x" * (cfg.max_event_bytes + 1)], SourceType.JSON,
                     store, now=now, cfg=cfg)
    assert ei.value.reason == RejectReason.EVENT_TOO_LARGE
    assert store.count() == 1  # only the seed remains


def test_cef_leef_syslog_normalization(cfg):
    store = EventStore(capacity=100)
    now = time.time()
    cef = "CEF:0|Acme|FW|2.1|400|Block|9|src=9.9.9.9 externalId=c1 rt=2026-09-22T10:00:00Z"
    leef = ("LEEF:2.0|IBM|Proventia|1.0|evt001\t"
            "src=8.8.8.8\tsev=5\tcat=attack\ttime=2026-09-22T10:00:00Z\tident=l1")
    syslog = "<13>Sep 22 10:00:00 web01 nginx: GET /admin 500"

    r = ingest_batch([cef], SourceType.CEF, store, now=now, cfg=cfg)
    assert r.accepted[0].event_id == "c1"
    assert r.accepted[0].severity == Severity.CRITICAL
    log_case("cef", cef, f"-> {r.accepted[0].event_id}/{r.accepted[0].severity.value}")

    r = ingest_batch([leef], SourceType.LEEF, store, now=now, cfg=cfg)
    assert r.accepted[0].event_id == "l1"
    assert r.accepted[0].severity == Severity.MEDIUM

    r = ingest_batch([syslog], SourceType.SYSLOG, store, now=now, cfg=cfg)
    assert r.accepted[0].event_type == "nginx"
    # <13> => pri 13 => severity code 13 & 7 = 5 => notice => low
    assert r.accepted[0].severity == Severity.LOW
    log_case("syslog", syslog, f"sev={r.accepted[0].severity.value}")


def test_malformed_text_sources_are_rejected_not_dropped(cfg):
    store = EventStore(capacity=100)
    now = time.time()
    for payload in ("CEF:broken", "LEEF|x|y", "nothing like a syslog line"):
        r = ingest_batch([payload], SourceType.CEF if payload.startswith("CEF") else SourceType.LEEF
                         if payload.startswith("LEEF") else SourceType.SYSLOG,
                         store, now=now, cfg=cfg)
        assert len(r.rejected) == 1
        assert r.rejected[0].reason == "malformed_payload"
        log_case("malformed-text", payload, f"reason={r.rejected[0].reason}")
