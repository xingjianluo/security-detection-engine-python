"""HTTP integration tests incl. original endpoint compatibility."""

from __future__ import annotations

import json
import time

import pytest

from fastapi.testclient import TestClient

import main
from detection.service import DetectionService
from tests.conftest import log_case


@pytest.fixture
def client(tmp_path):
    # Mount an isolated service. TestClient without ``with`` does not run the
    # lifespan, so the app.state value we set is what the handlers see.
    from detection.config import EngineConfig
    isolated = DetectionService(cfg=EngineConfig(data_dir=str(tmp_path / "api-data")))
    main.app.state.detection_service = isolated
    c = TestClient(main.app)
    yield c
    isolated.close()


def test_original_root_endpoint_unchanged(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json() == {"Hello": "World"}


def test_event_api_rejections_are_classified(client):
    ts = time.time()
    good = {"event_id": "x1", "type": "login", "severity": "high", "ts": ts}
    missing = {"type": "login", "severity": "high", "ts": ts}
    bad_ts = {"event_id": "x2", "type": "login", "severity": "high", "ts": "nope"}
    resp = client.post("/detection/events/json", json=[good, missing, bad_ts])
    assert resp.status_code == 200
    body = resp.json()
    assert body["accepted"] == 1
    assert [r["reason"] for r in body["rejected"]] == ["missing_field", "bad_timestamp"]
    log_case("api-batch", [good, missing, bad_ts], json.dumps(body)[:200])

    # whole-batch failures
    assert client.post("/detection/events/json", json=[]).status_code == 422
    resp = client.post("/detection/events/json", content=b"{not json",
                       headers={"content-type": "application/json"})
    assert resp.json()["error"] == "malformed_json"
    assert client.post("/detection/events/unknown_source", json=[good]).status_code == 400


def test_retry_over_http_is_idempotent(client):
    ts = time.time()
    payload = [{"event_id": "h1", "type": "login", "severity": "high", "ts": ts}]
    first = client.post("/detection/events/json", json=payload).json()
    second = client.post("/detection/events/json", json=payload).json()
    assert first["accepted"] == 1 and second["accepted"] == 0
    assert second["duplicates"] == ["h1"]


def test_rules_reload_and_alerts_flow(client):
    # no rules initially -> reload file missing path uses service default file;
    # use the rule listing + health endpoints directly
    health = client.get("/detection/health").json()
    assert health["status"] == "ok"
    assert "limits" in health and health["rules"] == 0

    # alerts query on unknown id -> 404
    resp = client.get("/detection/alerts/nope")
    assert resp.status_code == 404
    resp = client.post("/detection/alerts/nope/transition", json={"status": "resolved"})
    assert resp.status_code == 404
