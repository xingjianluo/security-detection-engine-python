"""Domain model types shared across the detection engine.

Only type declarations live here; normalization / lifecycle behaviour lives in
its own module so model files stay free of business logic.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib


class SourceType(str, enum.Enum):
    """Supported raw event source formats."""

    JSON = "json"          # canonical JSON envelope
    CEF = "cef"            # CEF:0|vendor|product|version|signature|name|severity|extensions
    LEEF = "leef"          # LEEF header + key/value pairs
    SYSLOG = "syslog"      # minimal "<pri>timestamp app: message" style


class Severity(str, enum.Enum):
    """Normalized severity. Ordering matters for suppression."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 10, "medium": 20, "high": 30, "critical": 40}[self.value]

    @classmethod
    def coerce(cls, raw: object) -> "Severity | None":
        if isinstance(raw, Severity):
            return raw
        if isinstance(raw, int):
            # Integers in 0..10 follow the CEF severity bands:
            # 0-3 low, 4-6 medium, 7-8 high, 9-10 critical.
            if 0 <= raw <= 10:
                if raw >= 9:
                    return cls.CRITICAL
                if raw >= 7:
                    return cls.HIGH
                if raw >= 4:
                    return cls.MEDIUM
                return cls.LOW
            for sev in (cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW):
                if raw >= sev.rank:
                    return sev
            return cls.LOW
        if isinstance(raw, str):
            v = raw.strip().lower()
            if v in ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10"):
                return cls.coerce(int(v) * 4)
            try:
                return cls(v)
            except ValueError:
                return None
        return None


class RuleFormatVersion(str, enum.Enum):
    V1 = "v1"
    V2 = "v2"


class ConditionOp(str, enum.Enum):
    """Rule condition operators.

    v1 supports EQ / NEQ / CONTAINS. v2 additionally supports GT / GTE /
    LT / LTE / REGEX. A v1 rule using a v2-only operator must be rejected
    with RULE_SEMANTIC_UNSUPPORTED.
    """

    EQ = "eq"
    NEQ = "neq"
    CONTAINS = "contains"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    REGEX = "regex"


class AlertStatus(str, enum.Enum):
    OPEN = "open"
    MERGED = "merged"
    SUPPRESSED = "suppressed"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


@dataclasses.dataclass(frozen=True)
class RuleCondition:
    field: str
    op: ConditionOp
    value: object


@dataclasses.dataclass(frozen=True)
class Rule:
    rule_id: str
    version: RuleFormatVersion
    name: str
    condition: RuleCondition
    severity: Severity
    rule_revision: int = 1
    # v2-only features (must be absent / default in v1 documents):
    dedupe_window_seconds: int | None = None
    suppress_key: str | None = None
    suppress_severity_ceiling: Severity | None = None
    # Digest of semantic content, computed at parse time.
    signature: str = ""


@dataclasses.dataclass(frozen=True)
class NormalizedEvent:
    """Canonical event every source format is normalized into."""

    event_id: str
    source: SourceType
    event_type: str
    severity: Severity
    occurred_at: float          # unix seconds, always UTC
    ingested_at: float
    source_ip: str | None
    target: str | None
    fields: dict[str, object]
    raw_size: int
    raw_digest: str

    def input_digest(self) -> str:
        """Stable digest of the normalized input for replay traceability."""
        payload = repr((
            self.event_id, self.source.value, self.event_type,
            self.severity.value, round(self.occurred_at, 6),
            self.source_ip, self.target,
            tuple(sorted(self.fields.items(), key=lambda kv: kv[0])),
        )).encode()
        return hashlib.sha256(payload).hexdigest()


@dataclasses.dataclass
class RejectedItem:
    index: int
    reason: str
    message: str
    raw_digest: str


@dataclasses.dataclass
class IngestResult:
    accepted: list[NormalizedEvent] = dataclasses.field(default_factory=list)
    rejected: list[RejectedItem] = dataclasses.field(default_factory=list)
    duplicate_ids: list[str] = dataclasses.field(default_factory=list)

    @property
    def accepted_count(self) -> int:
        return len(self.accepted)


@dataclasses.dataclass
class Alert:
    alert_id: str
    rule_id: str
    rule_revision: int
    rule_version: RuleFormatVersion
    rule_signature: str
    fingerprint: str
    severity: Severity
    status: AlertStatus
    first_event_id: str
    last_event_id: str
    event_count: int
    opened_at: float
    updated_at: float
    suppress_key: str | None = None
    parent_alert_id: str | None = None   # set when MERGED or SUPPRESSED
    event_ids: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Decision:
    """One append-only judgement record, used for replay & traceability."""

    seq: int
    event_id: str
    input_digest: str
    rule_id: str
    rule_revision: int
    rule_signature: str
    matched: bool
    reason: str
    alert_id: str | None
    at: float
