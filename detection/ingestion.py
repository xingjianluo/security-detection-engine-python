"""Multi-source event reception, validation and normalization.

Supported sources
-----------------
- ``json``:   canonical envelope
  ``{"event_id"?, "type", "severity", "ts", "src_ip"?, "target"?, "fields"?}``
- ``cef``:    ``CEF:0|vendor|product|version|signature|name|severity|k=v ...``
- ``leef``:   ``LEEF:2.0|vendor|product|version|event-id|key=value pairs``
- ``syslog``: ``<pri>Mon ... host app: message``

Every raw item is either normalized into exactly one :class:`NormalizedEvent`
or rejected with a distinct :class:`RejectReason`. Nothing is silently dropped.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re

from detection.config import EngineConfig
from detection.errors import EventRejectedError, RejectReason
from detection.models import (
    IngestResult,
    NormalizedEvent,
    RejectedItem,
    Severity,
    SourceType,
)
from detection.store import EventStore

_ISO_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
_SYSLOG_RE = re.compile(
    r"^(?P<pri><\d+>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+(?P<host>\S+)\s+(?P<app>\S+?):\s*(?P<msg>.*)$",
    re.DOTALL,
)

_FUTURE_SKEW_SECONDS = 60.0


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _raw_digest(raw_text: str) -> str:
    return hashlib.sha256(raw_text.encode("utf-8", "replace")).hexdigest()


def _reject(reason: RejectReason, message: str) -> None:
    raise EventRejectedError(reason, message)


def parse_timestamp(value: object, *, now: float, horizon: float) -> float:
    """Parse a timestamp; raise with BAD_TIMESTAMP / STALE_EVENT on failure.

    Accepts unix seconds (int/float) or ISO-8601 strings (``Z`` allowed).
    Future timestamps beyond a 60s skew are invalid. Event times older than
    ``horizon`` seconds are stale.
    """
    if isinstance(value, bool):
        _reject(RejectReason.BAD_TIMESTAMP, f"boolean timestamp: {value!r}")
    ts: float | None = None
    if isinstance(value, (int, float)):
        ts = float(value)
    elif isinstance(value, str):
        text = value.strip()
        if not _ISO_TS_RE.match(text):
            _reject(RejectReason.BAD_TIMESTAMP, f"unparseable timestamp: {value!r}")
        try:
            iso = text.replace("Z", "+00:00").replace(" ", "T", 1)
            dt = _dt.datetime.fromisoformat(iso)
        except ValueError:
            _reject(RejectReason.BAD_TIMESTAMP, f"unparseable timestamp: {value!r}")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.UTC)
        ts = dt.timestamp()
    else:
        _reject(RejectReason.BAD_TIMESTAMP, f"unsupported timestamp type: {type(value).__name__}")

    if ts <= 0 or ts != ts:  # NaN guard
        _reject(RejectReason.BAD_TIMESTAMP, f"illegal timestamp value: {value!r}")
    if ts > now + _FUTURE_SKEW_SECONDS:
        _reject(RejectReason.BAD_TIMESTAMP, f"timestamp {value!r} is too far in the future")
    if ts < now - horizon:
        raise EventRejectedError(
            RejectReason.STALE_EVENT,
            f"event time {value!r} is older than the {horizon:.0f}s horizon",
        )
    return ts


def _require_fields(obj: dict, fields: tuple[str, ...]) -> None:
    for name in fields:
        if name not in obj or obj[name] in (None, ""):
            _reject(RejectReason.MISSING_FIELD, f"missing required field: {name}")


def _build_event(
    *,
    event_id: str | None,
    source: SourceType,
    event_type: str,
    severity: object,
    ts: object,
    source_ip: str | None,
    target: str | None,
    fields: dict[str, object] | None,
    raw_text: str,
    now: float,
    cfg: EngineConfig,
) -> NormalizedEvent:
    if not event_id or not str(event_id).strip():
        _reject(RejectReason.MISSING_FIELD, "missing required field: event_id")
    sev = Severity.coerce(severity)
    if sev is None:
        _reject(RejectReason.MISSING_FIELD, f"invalid severity value: {severity!r}")
    occurred = parse_timestamp(ts, now=now, horizon=cfg.late_event_horizon_seconds)
    return NormalizedEvent(
        event_id=str(event_id),
        source=source,
        event_type=str(event_type),
        severity=sev,
        occurred_at=occurred,
        ingested_at=now,
        source_ip=source_ip,
        target=target,
        fields=dict(fields or {}),
        raw_size=len(raw_text.encode("utf-8", "replace")),
        raw_digest=_raw_digest(raw_text),
    )


# --------------------------------------------------------------------------- #
# Per-source parsers
# --------------------------------------------------------------------------- #

def _normalize_json(raw: object, *, now: float, cfg: EngineConfig) -> NormalizedEvent:
    if not isinstance(raw, dict):
        _reject(RejectReason.MALFORMED_PAYLOAD, "json event must be an object")
    _require_fields(raw, ("type", "severity", "ts"))
    return _build_event(
        event_id=raw.get("event_id"),
        source=SourceType.JSON,
        event_type=raw["type"],
        severity=raw["severity"],
        ts=raw["ts"],
        source_ip=raw.get("src_ip"),
        target=raw.get("target"),
        fields=raw.get("fields") if isinstance(raw.get("fields"), dict) else {},
        raw_text=json.dumps(raw, sort_keys=True, ensure_ascii=False),
        now=now,
        cfg=cfg,
    )


def _parse_kv(text: str) -> dict[str, str]:
    # Supports "k=v", "k = v" and quoted values.
    out: dict[str, str] = {}
    for match in re.finditer(
        r'([A-Za-z0-9_.]+)\s*=\s*("([^"]*)"|(?:(?!\s+[A-Za-z0-9_.]+\s*=)\S)*)',
        text,
    ):
        key = match.group(1)
        val = match.group(3) if match.group(3) is not None else match.group(2)
        out[key] = val
    return out


def _normalize_cef(raw: object, *, now: float, cfg: EngineConfig) -> NormalizedEvent:
    if not isinstance(raw, str):
        _reject(RejectReason.MALFORMED_PAYLOAD, "cef event must be a string")
    text = raw.strip()
    parts = text.split("|")
    if len(parts) < 8 or not parts[0].startswith("CEF:"):
        _reject(RejectReason.MALFORMED_PAYLOAD, "malformed CEF header")
    header, extension = parts[:7], "|".join(parts[7:])
    try:
        cef_version = int(header[0].split(":", 1)[1])
    except ValueError:
        _reject(RejectReason.MALFORMED_PAYLOAD, "malformed CEF version")
    signature, name, sev_raw = header[4], header[5], header[6]
    ext = _parse_kv(extension)
    sev_int: object = sev_raw
    if sev_raw.isdigit():
        sev_int = int(sev_raw)
    else:
        coerced = Severity.coerce(sev_raw)
        sev_int = sev_raw if coerced is None else coerced
    ts = ext.get("end") or ext.get("rt") or now
    return _build_event(
        event_id=ext.get("externalId"),
        source=SourceType.CEF,
        event_type=f"{signature}:{name}",
        severity=sev_int,
        ts=ts,
        source_ip=ext.get("src"),
        target=ext.get("dst") or ext.get("dhost"),
        fields={"cef_version": cef_version, "vendor": header[1], "product": header[2],
                "product_version": header[3], **ext},
        raw_text=text,
        now=now,
        cfg=cfg,
    )


def _normalize_leef(raw: object, *, now: float, cfg: EngineConfig) -> NormalizedEvent:
    if not isinstance(raw, str):
        _reject(RejectReason.MALFORMED_PAYLOAD, "leef event must be a string")
    text = raw.strip()
    head, sep, rest = text.partition("\t")
    parts = head.split("|")
    if len(parts) < 5 or not parts[0].startswith("LEEF"):
        _reject(RejectReason.MALFORMED_PAYLOAD, "malformed LEEF header")
    leef_version = parts[0].split(":", 1)[1] if ":" in parts[0] else "1.0"
    vendor, product, pversion, event_id = parts[1], parts[2], parts[3], parts[4]
    body: dict[str, str] = {}
    if leef_version.startswith("2"):
        body = _parse_kv(rest)
    else:
        # LEEF 1.0 uses tab-separated key=value pairs already in rest.
        for token in rest.split("\t"):
            if "=" in token:
                k, v = token.split("=", 1)
                body[k.strip()] = v.strip()
    ts = body.get("time") or body.get("devTime") or now
    severity: object = body.get("severity") or body.get("sev") or "low"
    if isinstance(severity, str) and severity.isdigit():
        severity = int(severity)
    return _build_event(
        event_id=body.get("ident") or body.get("externalId") or event_id,
        source=SourceType.LEEF,
        event_type=body.get("cat") or event_id,
        severity=severity,
        ts=ts,
        source_ip=body.get("src"),
        target=body.get("dst"),
        fields={"leef_version": leef_version, "vendor": vendor, "product": product,
                "product_version": pversion, **body},
        raw_text=text,
        now=now,
        cfg=cfg,
    )


_SYSLOG_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}


def _syslog_ts(text: str, now: float) -> float:
    if re.match(r"^\d{4}-", text):
        return parse_timestamp(text, now=now, horizon=100 * 365 * 24 * 3600.0)
    m = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})", text)
    if not m:
        _reject(RejectReason.BAD_TIMESTAMP, f"unparseable syslog timestamp: {text!r}")
    month = _SYSLOG_MONTHS.get(m.group(1))
    year = _dt.datetime.fromtimestamp(now, tz=_dt.UTC).year
    try:
        dt = _dt.datetime(year, month, int(m.group(2)), int(m.group(3)),
                          int(m.group(4)), int(m.group(5)), tzinfo=_dt.UTC)
    except ValueError:
        _reject(RejectReason.BAD_TIMESTAMP, f"invalid syslog date: {text!r}")
    ts = dt.timestamp()
    if ts > now + _FUTURE_SKEW_SECONDS:  # e.g. Jan log seen in December -> last year
        ts = dt.replace(year=year - 1).timestamp()
    return ts


def _normalize_syslog(raw: object, *, now: float, cfg: EngineConfig) -> NormalizedEvent:
    if not isinstance(raw, str):
        _reject(RejectReason.MALFORMED_PAYLOAD, "syslog event must be a string")
    text = raw.strip()
    match = _SYSLOG_RE.match(text)
    if not match:
        _reject(RejectReason.MALFORMED_PAYLOAD, "malformed syslog line")
    pri_text = (match.group("pri") or "").strip("<>")
    if pri_text:
        pri = int(pri_text)
        severity_code = pri & 0x7
        sev = {0: Severity.CRITICAL, 1: Severity.CRITICAL, 2: Severity.CRITICAL,
               3: Severity.HIGH, 4: Severity.MEDIUM, 5: Severity.LOW,
               6: Severity.LOW, 7: Severity.LOW}[severity_code]
        severity: object = sev
    else:
        severity = Severity.LOW
    occurred = _syslog_ts(match.group("ts"), now)
    message = match.group("msg")
    msg_hash = hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]
    return _build_event(
        event_id=f"syslog-{msg_hash}",
        source=SourceType.SYSLOG,
        event_type=match.group("app"),
        severity=severity,
        ts=occurred,
        source_ip=match.group("host"),
        target=None,
        fields={"message": message},
        raw_text=text,
        now=now,
        cfg=cfg,
    )


_PARSERS = {
    SourceType.JSON: _normalize_json,
    SourceType.CEF: _normalize_cef,
    SourceType.LEEF: _normalize_leef,
    SourceType.SYSLOG: _normalize_syslog,
}


def normalize_one(
    raw: object,
    source: SourceType,
    *,
    now: float,
    cfg: EngineConfig,
) -> NormalizedEvent:
    parser = _PARSERS[source]
    return parser(raw, now=now, cfg=cfg)


# --------------------------------------------------------------------------- #
# Batch ingestion
# --------------------------------------------------------------------------- #

def ingest_batch(
    raw_events: list[object],
    source: SourceType,
    store: EventStore,
    *,
    now: float,
    cfg: EngineConfig,
) -> IngestResult:
    """Validate every item, then commit accepted events atomically.

    Batch-level violations (empty / too many / too many bytes) raise before
    any item is parsed. Per-item violations are reported in ``rejected``.
    Capacity failures roll back: no event from the batch becomes visible.
    """
    if not isinstance(raw_events, list):
        _reject(RejectReason.MALFORMED_PAYLOAD, "batch must be a JSON array")
    if len(raw_events) == 0:
        _reject(RejectReason.BATCH_EMPTY, "event batch is empty")
    if len(raw_events) > cfg.max_batch_events:
        _reject(
            RejectReason.BATCH_TOO_LARGE,
            f"batch has {len(raw_events)} events, limit is {cfg.max_batch_events}",
        )

    # Pre-check raw sizes so an oversized item is classified distinctly and
    # the whole-batch byte budget is enforced deterministically.
    prepared: list[tuple[object, str]] = []
    total_bytes = 0
    for index, raw in enumerate(raw_events):
        if isinstance(raw, str):
            raw_text = raw
        else:
            try:
                raw_text = json.dumps(raw, sort_keys=True, ensure_ascii=False)
            except (TypeError, ValueError):
                _reject(RejectReason.MALFORMED_PAYLOAD, f"item {index} is not serializable")
        size = len(raw_text.encode("utf-8", "replace"))
        total_bytes += size
        if size > cfg.max_event_bytes:
            _reject(
                RejectReason.EVENT_TOO_LARGE,
                f"item {index} is {size} bytes, limit is {cfg.max_event_bytes}",
            )
        prepared.append((raw, raw_text))
    if total_bytes > cfg.max_batch_bytes:
        _reject(
            RejectReason.BATCH_TOO_LARGE,
            f"batch is {total_bytes} bytes, limit is {cfg.max_batch_bytes}",
        )

    result = IngestResult()
    normalized: list[NormalizedEvent] = []
    within_batch_dups: list[str] = []
    for index, (raw, raw_text) in enumerate(prepared):
        try:
            event = normalize_one(raw, source, now=now, cfg=cfg)
        except EventRejectedError as exc:
            result.rejected.append(
                RejectedItem(
                    index=index,
                    reason=exc.reason.value,
                    message=exc.message,
                    raw_digest=_raw_digest(raw_text),
                )
            )
            continue
        if any(e.event_id == event.event_id for e in normalized):
            # Repeated id inside this batch: first occurrence is the one kept.
            within_batch_dups.append(event.event_id)
        else:
            normalized.append(event)

    if normalized:
        existing_dups = store.add_batch(normalized)
        result.duplicate_ids = within_batch_dups + existing_dups
        result.accepted = [
            ev for ev in normalized if ev.event_id not in set(existing_dups)
        ]
    else:
        result.duplicate_ids = within_batch_dups
    return result
