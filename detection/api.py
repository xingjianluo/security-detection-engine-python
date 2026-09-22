"""HTTP surface for the detection engine, mounted under /detection."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from detection.errors import (
    CapacityError,
    DetectionError,
    EventRejectedError,
    RejectReason,
    RuleRejectedError,
    AlertTransitionError,
)
from detection.models import SourceType

router = APIRouter(prefix="/detection", tags=["detection"])
log = logging.getLogger("detection.api")

# Rejection codes that describe the whole request rather than one item.
_REQUEST_LEVEL = {
    RejectReason.BATCH_EMPTY,
    RejectReason.BATCH_TOO_LARGE,
    RejectReason.EVENT_TOO_LARGE,
    RejectReason.MALFORMED_JSON,
    RejectReason.MALFORMED_PAYLOAD,
    RejectReason.OVER_CAPACITY,
    RejectReason.ATOMIC_ROLLBACK,
}


def _service(request: Request):
    return request.app.state.detection_service


def _error_response(exc: DetectionError) -> JSONResponse:
    if isinstance(exc, CapacityError):
        status = 503
    elif exc.reason in (RejectReason.ALERT_NOT_FOUND, RejectReason.RULE_NOT_FOUND):
        status = 404
    elif exc.reason == RejectReason.ILLEGAL_TRANSITION:
        status = 409
    else:
        status = 422
    return JSONResponse(
        status_code=status,
        content={"error": exc.reason.value, "message": exc.message},
    )


async def _read_batch(request: Request, source: SourceType) -> list[object]:
    """Read the raw body. Text formats (cef/leef/syslog) accept either a
    JSON array of strings or a plain text body (one record per line)."""
    raw = await request.body()
    if not raw:
        raise EventRejectedError(RejectReason.BATCH_EMPTY, "empty request body")
    if source == SourceType.JSON:
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise EventRejectedError(RejectReason.MALFORMED_JSON, f"invalid JSON body: {exc}")
        if not isinstance(doc, list):
            raise EventRejectedError(RejectReason.MALFORMED_PAYLOAD,
                                     "body must be a JSON array of events")
        return doc
    text = raw.decode("utf-8", errors="replace").strip()
    try:
        doc = json.loads(text)
        if isinstance(doc, list):
            return doc
        raise EventRejectedError(RejectReason.MALFORMED_PAYLOAD,
                                 f"{source.value} JSON body must be an array of strings")
    except json.JSONDecodeError:
        # plain text: one record per line, blank lines are not allowed to
        # silently disappear -> they are kept and will be rejected upstream
        return [line for line in text.splitlines()]


@router.post("/events/{source}")
async def post_events(source: str, request: Request):
    try:
        src = SourceType(source)
    except ValueError:
        return JSONResponse(
            status_code=400,
            content={"error": RejectReason.UNKNOWN_SOURCE.value,
                     "message": f"unknown source {source!r}; expected one of "
                                f"{[s.value for s in SourceType]}"},
        )
    service = _service(request)
    try:
        batch = await _read_batch(request, src)
        result = service.ingest(batch, src)
    except EventRejectedError as exc:
        log.warning("ingest rejected: %s %s", exc.reason.value, exc.message)
        return _error_response(exc)
    except CapacityError as exc:
        log.warning("ingest over capacity: %s", exc.message)
        return _error_response(exc)
    return {
        "accepted": result.accepted_count,
        "duplicates": result.duplicate_ids,
        "rejected": [dataclasses_asdict(item) for item in result.rejected],
        "accepted_event_ids": [e.event_id for e in result.accepted],
    }


def dataclasses_asdict(item):
    return {"index": item.index, "reason": item.reason,
            "message": item.message, "raw_digest": item.raw_digest[:12]}


@router.post("/rules/reload")
async def reload_rules(request: Request):
    service = _service(request)
    try:
        ids = service.reload_rules()
    except RuleRejectedError as exc:
        log.warning("rules reload rejected: %s %s", exc.reason.value, exc.message)
        return _error_response(exc)
    return {"reloaded": ids, "count": len(ids)}


@router.get("/rules")
async def list_rules(request: Request):
    return {"rules": _service(request).list_rules()}


@router.get("/alerts")
async def list_alerts(request: Request):
    return {"alerts": _service(request).list_alerts()}


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str, request: Request):
    try:
        return _service(request).get_alert(alert_id)
    except AlertTransitionError as exc:
        return _error_response(exc)


@router.post("/alerts/{alert_id}/transition")
async def transition_alert(alert_id: str, body: dict, request: Request):
    target = body.get("status") if isinstance(body, dict) else None
    if not target:
        return JSONResponse(
            status_code=422,
            content={"error": RejectReason.ILLEGAL_TRANSITION.value,
                     "message": "body must be {'status': '...'}"},
        )
    try:
        return _service(request).transition_alert(alert_id, target)
    except AlertTransitionError as exc:
        return _error_response(exc)


@router.post("/alerts/merge")
async def merge_alerts(body: dict, request: Request):
    parent_id = body.get("parent_id") if isinstance(body, dict) else None
    child_id = body.get("child_id") if isinstance(body, dict) else None
    if not parent_id or not child_id:
        return JSONResponse(
            status_code=422,
            content={"error": RejectReason.ILLEGAL_TRANSITION.value,
                     "message": "body must be {'parent_id','child_id'}"},
        )
    try:
        return _service(request).merge_alerts(parent_id, child_id)
    except AlertTransitionError as exc:
        return _error_response(exc)


@router.post("/replay")
async def replay(request: Request):
    return _service(request).replay()


@router.post("/snapshot")
async def snapshot(request: Request):
    path = _service(request).save_snapshot()
    return {"snapshot": path}


@router.get("/health")
async def health(request: Request):
    return _service(request).health()
