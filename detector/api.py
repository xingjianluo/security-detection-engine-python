"""FastAPI 入口：在既有服务上扩展检测能力。

- ``GET /`` 保持原有 ``{"Hello": "World"}`` 行为；
- 新增 /health、/api/v1/events（多来源摄入）、规则管理、告警查询、
  状态跳转、快照与重放接口；
- 所有错误以统一 JSON 结构返回，``error.code`` 为可区分的机器原因码。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .config import Config
from .engine import Engine, build_engine, replay
from .errors import DetectionError


class EventBatchIn(BaseModel):
    source: str = "generic_json"
    events: list[dict[str, Any]] = Field(default_factory=list)


class RuleDocumentIn(BaseModel):
    document: dict[str, Any]


def _error_response(exc: DetectionError) -> JSONResponse:
    status = 422
    if exc.reason in ("backpressure_rejected", "backpressure_timeout"):
        status = 503
    if exc.reason == "alert_not_found":
        status = 404
    return JSONResponse(
        status_code=status,
        content={"error": {"code": exc.reason, "message": str(exc)}},
    )


def create_app(config: Config | None = None, *, engine: Engine | None = None) -> FastAPI:
    app = FastAPI(title="security-detection-engine")
    app.state.engine = engine or build_engine(config)
    engine_ref: Engine = app.state.engine

    @app.exception_handler(DetectionError)
    async def _on_detection_error(_request, exc: DetectionError):
        return _error_response(exc)

    # ---- 既有接口，行为保持不变 ----
    @app.get("/")
    def read_root():
        return {"Hello": "World"}

    @app.get("/health")
    def health():
        return {"status": "ok", "stats": engine_ref.stats()}

    # ---- 事件摄入 ----
    @app.post("/api/v1/events")
    def ingest_events(batch: EventBatchIn):
        result = engine_ref.ingest_batch(batch.events, source=batch.source)
        return {
            "accepted": [a.__dict__ for a in result.accepted],
            "rejected": [r.__dict__ for r in result.rejected],
        }

    @app.get("/api/v1/events/{event_id}")
    def get_event(event_id: str):
        event = engine_ref.get_event(event_id)
        if event is None:
            return JSONResponse(status_code=404,
                                content={"error": {"code": "event_not_found",
                                                   "message": event_id}})
        return event.to_dict()

    # ---- 规则 ----
    @app.post("/api/v1/rules")
    def publish_rules(doc: RuleDocumentIn):
        revision = engine_ref.publish_rules_document(doc.document)
        return {"revision": revision}

    @app.get("/api/v1/rules")
    def get_rules():
        rules = engine_ref.store.active_rules()
        return {
            "revision": engine_ref.store.current_revision(),
            "rules": [
                {
                    "rule_id": r.rule_id, "version": r.version,
                    "revision": r.revision, "name": r.name,
                    "event_type": r.event_type, "severity": r.severity.value,
                    "conditions": r.conditions,
                    "dedup_window_s": r.dedup_window_s,
                    "suppress_window_s": r.suppress_window_s,
                    "suppress_max_severity": (
                        r.suppress_max_severity.value
                        if r.suppress_max_severity else None),
                    "correlation_key": r.correlation_key,
                    "merge_key": r.merge_key, "enabled": r.enabled,
                }
                for r in rules
            ],
        }

    # ---- 告警 ----
    @app.get("/api/v1/alerts")
    def list_alerts(state: str | None = Query(default=None)):
        alerts_ = engine_ref.list_alerts()
        if state:
            alerts_ = [a for a in alerts_ if a.state.value == state]
        return {"alerts": [a.to_dict() for a in alerts_]}

    @app.get("/api/v1/alerts/{alert_id}")
    def get_alert(alert_id: str):
        alert = engine_ref.get_alert(alert_id)
        if alert is None:
            return JSONResponse(status_code=404,
                                content={"error": {"code": "alert_not_found",
                                                   "message": alert_id}})
        return alert.to_dict()

    @app.post("/api/v1/alerts/{alert_id}/acknowledge")
    def acknowledge_alert(alert_id: str):
        return engine_ref.acknowledge(alert_id).to_dict()

    @app.post("/api/v1/alerts/{alert_id}/resolve")
    def resolve_alert(alert_id: str):
        return engine_ref.resolve(alert_id).to_dict()

    @app.post("/api/v1/alerts/{alert_id}/reopen")
    def reopen_alert(alert_id: str):
        return engine_ref.reopen(alert_id).to_dict()

    @app.post("/api/v1/alerts/tick-suppress-expiry")
    def tick_suppress():
        return {"reopened": [a.to_dict() for a in engine_ref.suppress_expired_tick()]}

    # ---- 快照与重放 ----
    @app.post("/api/v1/snapshot")
    def take_snapshot():
        path = engine_ref.save_snapshot()
        return {"snapshot": str(path)}

    @app.get("/api/v1/journal")
    def get_journal():
        return {"entries": [
            {"seq": e.seq, "ts": e.ts.isoformat(), "kind": e.kind,
             "payload": e.payload, "digest": e.digest}
            for e in engine_ref.journal()
        ]}

    @app.post("/api/v1/replay")
    def replay_journal():
        _engine, report = replay(engine_ref.config.journal_path, engine_ref.config)
        return {"report": report, "stats": _engine.stats()}

    return app
