"""HTTP 入口：既有接口行为保持；错误码可区分；多来源摄入可用。"""

import logging

import pytest
from fastapi.testclient import TestClient

from detector.api import create_app
from detector.config import Config
from detector.models import utcnow

log = logging.getLogger("detector.tests")


@pytest.fixture
def client(tmp_path):
    cfg = Config(rules_dir=tmp_path / "rules", data_dir=tmp_path / "data",
                 future_tolerance_s=3600)
    return TestClient(create_app(cfg))


def test_legacy_root_unchanged(client):
    assert client.get("/").json() == {"Hello": "World"}


def test_full_flow_via_http(client):
    # 发布规则
    doc = {"format_version": 2, "revision": 1, "rules": [
        {"id": "brute", "event_type": "login", "severity": "high",
         "conditions": {"all": [
             {"field": "src_ip", "op": "prefix", "value": "10."}]},
         "correlation_key": ["src_ip", "user"],
         "merge_key": ["rule_id", "src_ip"],
         "suppress": {"window_s": 600, "max_severity": "medium"}}]}
    assert client.post("/api/v1/rules", json={"document": doc}).json() == {
        "revision": 1}

    # 未支持字段 -> 422 且原因码可区分
    bad_doc = {"format_version": 2, "revision": 2, "rules": [
        {"id": "x", "event_type": "login", "severity": "high",
         "quantum_score": 3}]}
    resp = client.post("/api/v1/rules", json={"document": bad_doc})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "unsupported_rule_field"

    now = utcnow().isoformat()
    resp = client.post("/api/v1/events", json={
        "source": "generic_json",
        "events": [
            {"event_id": "g1", "type": "login", "severity": "high",
             "timestamp": now, "src_ip": "10.0.0.1", "user": "bob"},
            {"event_id": "g1", "type": "login", "severity": "high",
             "timestamp": now, "src_ip": "10.0.0.1", "user": "bob"},
            {"nope": True},
        ]})
    body = resp.json()
    assert len(body["accepted"]) == 2
    assert body["accepted"][1]["dedup_hit"] is True
    assert body["rejected"][0]["reason"] == "missing_field"

    # CEF webhook 来源
    resp = client.post("/api/v1/events", json={
        "source": "syslog_cef",
        "events": [{"id": "c1", "signatureId": "login", "rt": now,
                    "severity": 9, "src": "10.2.2.2", "suser": "bob"}]})
    assert resp.json()["accepted"][0]["outcome"] == "accepted"

    alerts = client.get("/api/v1/alerts").json()["alerts"]
    assert alerts and alerts[0]["rule_revision"] == 1
    aid = alerts[0]["alert_id"]
    assert client.post(f"/api/v1/alerts/{aid}/acknowledge").json()[
        "state"] == "acknowledged"
    assert client.post(f"/api/v1/alerts/{aid}/resolve").json()[
        "state"] == "resolved"
    illegal = client.post(f"/api/v1/alerts/{aid}/acknowledge")
    assert illegal.status_code == 422
    assert illegal.json()["error"]["code"] == "illegal_state_transition"

    assert client.get(f"/api/v1/events/g1").status_code == 200
    assert client.get("/api/v1/events/missing").status_code == 404
    journal = client.get("/api/v1/journal").json()["entries"]
    assert any(e["kind"] == "alert_opened" for e in journal)
    snapshot = client.post("/api/v1/snapshot")
    assert snapshot.status_code == 200
    log.info("HTTP 全流程通过，告警 %s 条，流水 %s 条", len(alerts), len(journal))


def test_retention_and_archive_endpoints(tmp_path):
    """HTTP：evict 结果与水位可见；reject_new 返回明确 503 原因码；
    include_archive 重放入口可用。"""
    from detector.engine import build_engine

    d = tmp_path / "data"
    cfg = Config(
        rules_dir=tmp_path / "rules", data_dir=d,
        journal_path=d / "journal.jsonl", snapshot_path=d / "snapshot.json",
        archive_dir=d / "archive", future_tolerance_s=3600,
        retention_max_records=12, retention_max_bytes=10**9,
        retention_policy="reject_new", snapshot_every=0)
    client = TestClient(create_app(cfg, persist=True))
    doc = {"format_version": 2, "revision": 1, "rules": [
        {"id": "brute", "event_type": "login", "severity": "high",
         "conditions": {"all": [
             {"field": "src_ip", "op": "prefix", "value": "10."}]}}]}
    assert client.post("/api/v1/rules", json={"document": doc}).status_code == 200
    now = utcnow().isoformat()
    for i in range(4):
        body = client.post("/api/v1/events", json={"events": [
            {"event_id": f"h{i}", "type": "login", "severity": "high",
             "timestamp": now, "src_ip": f"10.0.{i}.1", "user": "b"}]}).json()
        assert "retention" in body and body["evicted"] == 0
    resp = client.post("/api/v1/events", json={"events": [
        {"event_id": "overflow", "type": "login", "severity": "high",
         "timestamp": now, "src_ip": "10.9.9.9", "user": "b"}]})
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "retention_full"

    stats = client.get("/health").json()["stats"]
    assert stats["retention"]["policy"] == "reject_new"
    assert stats["archive"]["enabled"] is True

    rep = client.post("/api/v1/replay?include_archive=false")
    assert rep.status_code == 200
    assert rep.json()["included_archive"] is False
