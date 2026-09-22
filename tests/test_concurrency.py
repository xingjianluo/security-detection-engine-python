"""Concurrent delivery and backpressure tests."""

from __future__ import annotations

import threading
import time

import pytest

from detection.config import EngineConfig
from detection.errors import CapacityError
from detection.models import SourceType
from tests.conftest import log_case, write_rules

RULE = {
    "id": "r", "version": "v2", "revision": 1, "name": "login fail",
    "condition": {"field": "event_type", "op": "eq", "value": "login_fail"},
    "severity": "high", "dedupe_window_seconds": 3600,
}


def _ev(i: int) -> dict:
    return {"event_id": f"c{i}", "type": "login_fail", "severity": "high",
            "ts": time.time()}


def test_concurrent_identical_delivery_takes_effect_once(tmp_path):
    from detection.service import DetectionService
    cfg = EngineConfig(data_dir=str(tmp_path), max_events_in_memory=10_000)
    svc = DetectionService(cfg=cfg)
    write_rules(str(tmp_path), [RULE])
    svc.reload_rules()

    payload = [_ev(0)]
    results: list[int] = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        r = svc.ingest([dict(payload[0])], SourceType.JSON)
        results.append(r.accepted_count)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert svc.events.count() == 1
    assert sum(results) == 1
    assert results.count(0) == 7
    # exactly one alert, counted once
    assert len(svc.list_alerts()) == 1
    svc.close()
    log_case("concurrent-same-id", "8 threads x same event",
             f"stored=1 accepted_sum={sum(results)}")


def test_concurrent_distinct_events_no_count_drift(tmp_path):
    from detection.service import DetectionService
    cfg = EngineConfig(data_dir=str(tmp_path / "b"), max_events_in_memory=50_000)
    (tmp_path / "b").mkdir(exist_ok=True)
    svc = DetectionService(cfg=cfg)
    write_rules(cfg.data_dir, [RULE])
    svc.reload_rules()

    def worker(base: int):
        batch = [_ev(i) for i in range(base, base + 50)]
        svc.ingest(batch, SourceType.JSON)

    threads = [threading.Thread(target=worker, args=(b,))
               for b in range(0, 500, 50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert svc.events.count() == 500
    decisions = [d for d in svc.journal.all() if d.matched]
    assert len(decisions) == 500  # no lost / duplicated detection
    svc.close()
    log_case("concurrent-distinct", "10 threads x 50 events",
             f"events=500 decisions={len(decisions)}")


def test_backpressure_rejects_without_partial_state(tmp_path):
    from detection.service import DetectionService
    cfg = EngineConfig(
        data_dir=str(tmp_path / "c"),
        max_events_in_memory=5, max_open_alerts=100,
    )
    (tmp_path / "c").mkdir(exist_ok=True)
    svc = DetectionService(cfg=cfg)
    write_rules(cfg.data_dir, [RULE])
    svc.reload_rules()

    svc.ingest([_ev(i) for i in range(5)], SourceType.JSON)
    assert svc.events.count() == 5

    with pytest.raises(CapacityError):
        # batch of 6 cannot fit: must fail atomically
        svc.ingest([_ev(i) for i in range(100, 106)], SourceType.JSON)

    assert svc.events.count() == 5
    svc.close()
    log_case("backpressure", "store cap 5, batch of 6 rejected",
             "store still 5, no partial commit")
