"""Typed errors for the local detection engine.

Every rejection path uses one of the enumerated ``RejectReason`` codes so
callers can distinguish *why* an event / rule / transition was refused.
"""

from __future__ import annotations

import enum


class RejectReason(str, enum.Enum):
    """Stable, user-visible rejection reason codes."""

    # Event ingestion
    MALFORMED_JSON = "malformed_json"
    MALFORMED_PAYLOAD = "malformed_payload"
    MISSING_FIELD = "missing_field"
    BAD_TIMESTAMP = "bad_timestamp"
    STALE_EVENT = "stale_event"
    EVENT_TOO_LARGE = "event_too_large"
    BATCH_TOO_LARGE = "batch_too_large"
    UNKNOWN_SOURCE = "unknown_source"
    BATCH_EMPTY = "batch_empty"
    OVER_CAPACITY = "over_capacity"
    ATOMIC_ROLLBACK = "atomic_rollback"

    # Rules
    RULE_MISSING_FIELD = "rule_missing_field"
    RULE_VERSION_UNSUPPORTED = "rule_version_unsupported"
    RULE_FIELD_UNSUPPORTED = "rule_field_unsupported"
    RULE_SEMANTIC_UNSUPPORTED = "rule_semantic_unsupported"
    RULE_DUPLICATE_ID = "rule_duplicate_id"
    RULE_NOT_FOUND = "rule_not_found"

    # Alert lifecycle
    ILLEGAL_TRANSITION = "illegal_transition"
    ALERT_NOT_FOUND = "alert_not_found"


class DetectionError(Exception):
    """Base class for all engine errors."""

    reason: RejectReason = RejectReason.MALFORMED_JSON

    def __init__(self, reason: RejectReason, message: str = "") -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message

    def __str__(self) -> str:
        return f"{self.reason.value}: {self.message}"


class EventRejectedError(DetectionError):
    """An individual event (or a whole batch) was rejected."""


class RuleRejectedError(DetectionError):
    """A rule document was rejected."""


class AlertTransitionError(DetectionError):
    """An illegal alert lifecycle transition was attempted."""


class CapacityError(DetectionError):
    """Backpressure limit reached."""
