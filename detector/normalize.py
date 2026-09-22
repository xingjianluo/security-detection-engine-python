"""多来源事件格式接收与归一化。

支持三种来源格式，映射关系显式声明，任何必填字段缺失、时间非法、
严重级别无法识别都按可区分的原因拒绝，绝不静默丢弃：

generic_json : 标准 JSON 事件
    event_id / type / severity(info..critical) / timestamp / src_ip /
    dst_ip / user / host / action
syslog_cef   : CEF 风格字段
    id / deviceProduct / signatureId / rt(epoch 毫秒或 ISO) /
    severity(0-10 整数) / src / dst / suser / dhost / act / msg
alert_webhook: 外部告警 webhook
    uuid / alert_type / level(1-5) / created_at / source_ip /
    account / hostname
"""

from __future__ import annotations

from typing import Any, Callable

from .errors import (
    InvalidTimestampError,
    MissingFieldError,
    UnknownSourceError,
)
from .models import Event, Severity, input_digest, parse_ts, utcnow


SOURCE_FORMATS = ("generic_json", "syslog_cef", "alert_webhook")

_EXTRA_SOURCES: dict[str, Callable[[dict[str, Any]], Event]] = {}


def register_source(name: str, fn: Callable[[dict[str, Any]], Event] | None = None) -> None:
    """注册一个新的来源格式（扩展点），可作装饰器使用。"""

    def _do_register(func: Callable[[dict[str, Any]], Event]):
        _EXTRA_SOURCES[name] = func
        return func

    if fn is not None:
        _do_register(fn)
        return None
    return _do_register


def _require(payload: dict[str, Any], key: str) -> Any:
    if key not in payload or payload[key] in (None, ""):
        raise MissingFieldError(f"missing required field: {key!r}", reason="missing_field")
    return payload[key]


_SEV_NAMES = {s.value: s for s in Severity}


def _severity_by_name(raw: Any, field_name: str) -> Severity:
    if not isinstance(raw, str) or raw.lower() not in _SEV_NAMES:
        raise MissingFieldError(
            f"field {field_name!r} has unrecognized severity: {raw!r}",
            reason="invalid_severity",
        )
    return Severity(raw.lower())


def _time(raw: Any, field_name: str):
    try:
        return parse_ts(raw)
    except ValueError as exc:
        raise InvalidTimestampError(
            f"field {field_name!r}: {exc}", reason="invalid_timestamp"
        ) from exc


def _normalize_generic_json(payload: dict[str, Any]) -> Event:
    event_id = str(_require(payload, "event_id"))
    event_type = str(_require(payload, "type"))
    severity = _severity_by_name(_require(payload, "severity"), "severity")
    occurred_at = _time(_require(payload, "timestamp"), "timestamp")
    return Event(
        event_id=event_id,
        source="generic_json",
        event_type=event_type,
        severity=severity,
        occurred_at=occurred_at,
        ingested_at=utcnow(),
        src_ip=payload.get("src_ip"),
        dst_ip=payload.get("dst_ip"),
        user=payload.get("user"),
        host=payload.get("host"),
        action=payload.get("action"),
        raw=dict(payload),
        digest=input_digest(payload),
    )


def _cef_severity(raw: Any) -> Severity:
    if isinstance(raw, bool) or not isinstance(raw, int) or not 0 <= raw <= 10:
        raise MissingFieldError(
            f"CEF field 'severity' must be int 0..10, got {raw!r}",
            reason="invalid_severity",
        )
    # CEF 0-3 low, 4-6 medium, 7-8 high, 9-10 critical
    if raw <= 3:
        return Severity.LOW
    if raw <= 6:
        return Severity.MEDIUM
    if raw <= 8:
        return Severity.HIGH
    return Severity.CRITICAL


def _normalize_syslog_cef(payload: dict[str, Any]) -> Event:
    event_id = str(_require(payload, "id"))
    sig = payload.get("signatureId")
    msg_type = payload.get("deviceProduct")
    if sig is None and msg_type is None:
        raise MissingFieldError(
            "CEF event requires 'signatureId' or 'deviceProduct' to derive type",
            reason="missing_field",
        )
    event_type = str(sig if sig is not None else msg_type)
    severity = _cef_severity(_require(payload, "severity"))
    occurred_at = _time(_require(payload, "rt"), "rt")
    return Event(
        event_id=event_id,
        source="syslog_cef",
        event_type=event_type,
        severity=severity,
        occurred_at=occurred_at,
        ingested_at=utcnow(),
        src_ip=payload.get("src"),
        dst_ip=payload.get("dst"),
        user=payload.get("suser"),
        host=payload.get("dhost") or payload.get("shost"),
        action=payload.get("act"),
        raw=dict(payload),
        digest=input_digest(payload),
    )


def _webhook_level(raw: Any) -> Severity:
    if isinstance(raw, bool) or not isinstance(raw, int) or not 1 <= raw <= 5:
        raise MissingFieldError(
            f"webhook field 'level' must be int 1..5, got {raw!r}",
            reason="invalid_severity",
        )
    return {
        1: Severity.INFO,
        2: Severity.LOW,
        3: Severity.MEDIUM,
        4: Severity.HIGH,
        5: Severity.CRITICAL,
    }[raw]


def _normalize_alert_webhook(payload: dict[str, Any]) -> Event:
    event_id = str(_require(payload, "uuid"))
    event_type = str(_require(payload, "alert_type"))
    severity = _webhook_level(_require(payload, "level"))
    occurred_at = _time(_require(payload, "created_at"), "created_at")
    return Event(
        event_id=event_id,
        source="alert_webhook",
        event_type=event_type,
        severity=severity,
        occurred_at=occurred_at,
        ingested_at=utcnow(),
        src_ip=payload.get("source_ip"),
        dst_ip=None,
        user=payload.get("account"),
        host=payload.get("hostname"),
        action=None,
        raw=dict(payload),
        digest=input_digest(payload),
    )


_BUILTIN: dict[str, Callable[[dict[str, Any]], Event]] = {
    "generic_json": _normalize_generic_json,
    "syslog_cef": _normalize_syslog_cef,
    "alert_webhook": _normalize_alert_webhook,
}


def normalize_event(payload: dict[str, Any], *, source: str) -> Event:
    """把单一来源负载归一为 :class:`Event`。

    缺失必填字段抛 MissingFieldError；时间非法抛 InvalidTimestampError；
    未知来源抛 UnknownSourceError；负载不是 JSON 对象统一归类为
    MissingFieldError(malformed_payload)。
    """
    if not isinstance(payload, dict):
        raise MissingFieldError(
            f"event payload must be a JSON object, got {type(payload).__name__}",
            reason="malformed_payload",
        )
    fn = _BUILTIN.get(source) or _EXTRA_SOURCES.get(source)
    if fn is None:
        raise UnknownSourceError(
            f"unknown source format: {source!r}; supported={sorted(_BUILTIN)}",
            reason="unknown_source",
        )
    return fn(payload)


def normalize_batch(
    payloads: list[dict[str, Any]], *, source: str
) -> tuple[list[Event], list[tuple[str, str, str]]]:
    """归一化整批。

    返回 ``(events, rejected)``，rejected 项为
    ``(event_id 占位, reason, detail)``；单条非法不影响同批其它事件，
    由引擎层决定事务边界。
    """
    events: list[Event] = []
    rejected: list[tuple[str, str, str]] = []
    for index, payload in enumerate(payloads):
        placeholder = ""
        try:
            if isinstance(payload, dict):
                placeholder = str(
                    payload.get("event_id")
                    or payload.get("id")
                    or payload.get("uuid")
                    or f"#{index}"
                )
            event = normalize_event(payload, source=source)
            events.append(event)
        except Exception as exc:  # noqa: BLE001 - 归一化阶段需归类全部失败
            reason = getattr(exc, "reason", "event_validation_failed")
            rejected.append((placeholder, reason, str(exc)))
    return events, rejected
