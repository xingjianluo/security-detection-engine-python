"""并发投递：同标识并发只生效一次；计数无漂移；并发查询/状态变更一致。"""

import logging
import threading
from datetime import timedelta

from detector.errors import BackpressureError
from detector.models import utcnow
from .helpers import event_payload

log = logging.getLogger("detector.tests")


def test_concurrent_same_id_applies_once(engine):
    now = utcnow().isoformat()
    threads_n = 64
    barrier = threading.Barrier(threads_n)
    dedup_hits = []
    lock = threading.Lock()

    def fire(i):
        barrier.wait()
        result = engine.ingest_batch(
            [event_payload("same-id", timestamp=now, user=str(i))],
            source="generic_json")
        with lock:
            dedup_hits.append(result.accepted[0].dedup_hit)

    threads = [threading.Thread(target=fire, args=(i,)) for i in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert dedup_hits.count(False) == 1
    assert dedup_hits.count(True) == threads_n - 1
    assert engine.stats()["events"] == 1
    # 不产生重复告警
    assert len(engine.list_alerts()) == 1
    log.info("并发 %s 次同 id 投递：1 次生效，%s 次判重",
             threads_n, threads_n - 1)


def test_concurrent_distinct_events_no_count_drift(engine):
    now = utcnow().isoformat()
    per_thread, threads_n = 200, 16
    barrier = threading.Barrier(threads_n)

    def worker(w):
        batch = [event_payload(f"e-{w}-{i}", timestamp=now,
                               src_ip="10.1.0.1")
                 for i in range(per_thread)]
        barrier.wait()
        engine.ingest_batch(batch, source="generic_json")

    threads = [threading.Thread(target=worker, args=(w,))
               for w in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert engine.stats()["events"] == per_thread * threads_n


def test_backpressure_rejects_without_partial_state(tmp_path):
    from detector.config import Config
    from detector.engine import Engine
    from detector.models import utcnow

    cfg = Config(rules_dir=tmp_path / "rules",
                 max_inflight_events=5, future_tolerance_s=3600)
    eng = Engine(cfg)
    eng.publish_rules_document({"format_version": 2, "revision": 1, "rules": [
        {"id": "r", "event_type": "login", "severity": "info",
         "conditions": {"all": [
             {"field": "src_ip", "op": "prefix", "value": "10."}]}}]})
    now = utcnow().isoformat()
    try:
        eng.ingest_batch(
            [event_payload(f"bp{i}", timestamp=now) for i in range(6)],
            source="generic_json")
        raise AssertionError("应当触发背压拒绝")
    except BackpressureError as exc:
        assert exc.reason == "backpressure_rejected"
    assert eng.stats()["events"] == 0
    assert eng.stats()["inflight"] == 0   # 许可被释放，无资源泄漏


def test_concurrent_state_transitions_serialized(engine):
    now = utcnow().isoformat()
    engine.ingest_batch([event_payload("st1", timestamp=now)],
                        source="generic_json")
    alert_id = engine.list_alerts()[0].alert_id
    outcomes = []
    lock = threading.Lock()

    def record(fn, ok_label):
        try:
            fn(alert_id)
            with lock:
                outcomes.append(ok_label)
        except Exception as exc:  # noqa: BLE001
            with lock:
                outcomes.append(getattr(exc, "reason", "error"))

    phase1 = threading.Barrier(11)
    phase2 = threading.Barrier(11)

    def acker():
        phase1.wait()
        record(engine.acknowledge, "ack-ok")
        phase2.wait()

    # 阶段一：10 个并发 ack（同态 no-op 合法，OPEN->ACK 只发生一次）
    threads = [threading.Thread(target=acker) for _ in range(10)]
    for t in threads:
        t.start()
    phase1.wait()
    phase2.wait()
    for t in threads:
        t.join()
    assert engine.get_alert(alert_id).state.value == "acknowledged"
    assert outcomes.count("ack-ok") == 10

    # 阶段二：10 个并发 resolve；ACK->RESOLVED 只生效一次，其余同态 no-op
    outcomes.clear()
    resolver_done = threading.Barrier(10)

    def resolver():
        resolver_done.wait()
        record(engine.resolve, "resolve-ok")

    threads = [threading.Thread(target=resolver) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    final = engine.get_alert(alert_id)
    assert final.state.value == "resolved"
    assert outcomes.count("resolve-ok") == 10
    log.info("并发同态跳转：ack=%s resolve=%s 终态=%s",
             "10/10 ok", "10/10 ok", final.state.value)
