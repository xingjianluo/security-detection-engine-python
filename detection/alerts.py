"""Alert lifecycle state machine.

Legal transitions (everything else is rejected as ILLEGAL_TRANSITION)::

    OPEN         -> MERGED | SUPPRESSED | ACKNOWLEDGED | RESOLVED
    ACKNOWLEDGED -> RESOLVED
    SUPPRESSED   -> OPEN          (a higher-severity event reopens it)
    MERGED       -> (terminal)
    RESOLVED     -> (terminal)
"""

from __future__ import annotations

import dataclasses

from detection.errors import AlertTransitionError, RejectReason
from detection.models import Alert, AlertStatus

TRANSITIONS: dict[AlertStatus, set[AlertStatus]] = {
    AlertStatus.OPEN: {
        AlertStatus.MERGED,
        AlertStatus.SUPPRESSED,
        AlertStatus.ACKNOWLEDGED,
        AlertStatus.RESOLVED,
    },
    AlertStatus.ACKNOWLEDGED: {AlertStatus.RESOLVED},
    AlertStatus.MERGED: set(),
    AlertStatus.SUPPRESSED: {AlertStatus.OPEN},
    AlertStatus.RESOLVED: set(),
}


def can_transition(current: AlertStatus, target: AlertStatus) -> bool:
    return target in TRANSITIONS[current]


def transition(alert: Alert, target: AlertStatus, *, now: float) -> Alert:
    """Return an updated alert if the transition is legal, else raise.

    The incoming alert object is never mutated; a new value is returned.
    """
    current = alert.status
    if target == current:
        # A no-op is only acceptable for non-terminal states; repeating a
        # terminal action (merge/resolve) is an illegal transition.
        if current in (AlertStatus.MERGED, AlertStatus.RESOLVED):
            raise AlertTransitionError(
                RejectReason.ILLEGAL_TRANSITION,
                f"alert {alert.alert_id}: {current.value} is terminal",
            )
        return dataclasses.replace(alert, updated_at=now)
    if not can_transition(current, target):
        raise AlertTransitionError(
            RejectReason.ILLEGAL_TRANSITION,
            f"alert {alert.alert_id}: {current.value} -> {target.value} is not allowed",
        )
    return dataclasses.replace(alert, status=target, updated_at=now)
