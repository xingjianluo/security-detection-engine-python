"""Thread-safe in-memory stores with atomic batch commit and capacity caps."""

from __future__ import annotations

import dataclasses
import threading

from detection.errors import CapacityError, RejectReason
from detection.models import (
    Alert,
    AlertStatus,
    Decision,
    NormalizedEvent,
    Rule,
)


class EventStore:
    """Idempotent event storage.

    ``event_id`` is the idempotency key. Concurrent and retried inserts of the
    same id take effect exactly once. Batch commits are atomic: capacity is
    verified *before* any mutation, so a failure leaves no partial state.
    """

    def __init__(self, capacity: int) -> None:
        self._lock = threading.RLock()
        self._events: dict[str, NormalizedEvent] = {}
        self._capacity = capacity

    def add_batch(self, events: list[NormalizedEvent]) -> list[str]:
        """Atomically add events. Returns ids rejected as duplicates.

        Duplicates = ids already stored or repeated within this batch.
        Raises ``CapacityError`` without mutating state if the cap is exceeded.
        """
        seen: set[str] = set()
        unique: list[NormalizedEvent] = []
        duplicates: list[str] = []
        for ev in events:
            if ev.event_id in seen:
                duplicates.append(ev.event_id)
                continue
            seen.add(ev.event_id)
            unique.append(ev)

        with self._lock:
            fresh = [ev for ev in unique if ev.event_id not in self._events]
            duplicates.extend(
                ev.event_id for ev in unique if ev.event_id in self._events
            )
            if len(self._events) + len(fresh) > self._capacity:
                raise CapacityError(
                    RejectReason.OVER_CAPACITY,
                    f"event store capacity {self._capacity} exceeded",
                )
            # Commit point: only reached after every check succeeded.
            for ev in fresh:
                self._events[ev.event_id] = ev
        return duplicates

    def has(self, event_id: str) -> bool:
        with self._lock:
            return event_id in self._events

    def get(self, event_id: str) -> NormalizedEvent | None:
        with self._lock:
            return self._events.get(event_id)

    def all(self) -> list[NormalizedEvent]:
        with self._lock:
            return list(self._events.values())

    def count(self) -> int:
        with self._lock:
            return len(self._events)


class RuleStore:
    """Keeps *every* revision of every rule.

    Active rules are keyed by ``rule_id``; historical revisions are retained
    keyed by ``(rule_id, rule_revision)`` so replay can resolve the exact
    revision that produced a historical alert.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._rules: dict[str, Rule] = {}
        self._history: dict[tuple[str, int], Rule] = {}

    def put(self, rule: Rule) -> None:
        with self._lock:
            self._rules[rule.rule_id] = rule
            self._history[(rule.rule_id, rule.rule_revision)] = rule

    def replace_all(self, rules: list[Rule]) -> None:
        """Atomically swap the active set; history is always preserved."""
        with self._lock:
            active = {rule.rule_id: rule for rule in rules}
            history = dict(self._history)
            for rule in rules:
                history[(rule.rule_id, rule.rule_revision)] = rule
            self._rules = active
            self._history = history

    def get(self, rule_id: str) -> Rule | None:
        with self._lock:
            return self._rules.get(rule_id)

    def get_revision(self, rule_id: str, revision: int) -> Rule | None:
        with self._lock:
            return self._history.get((rule_id, revision))

    def all(self) -> list[Rule]:
        with self._lock:
            return list(self._rules.values())

    def snapshot(self) -> dict[str, Rule]:
        """Point-in-time copy used by evaluation and replay."""
        with self._lock:
            return dict(self._rules)


class AlertStore:
    def __init__(self, max_open_alerts: int) -> None:
        self._lock = threading.RLock()
        self._alerts: dict[str, Alert] = {}
        self._max_open = max_open_alerts

    def add(self, alert: Alert) -> None:
        with self._lock:
            if alert.status == AlertStatus.OPEN and self._open_count_locked() >= self._max_open:
                raise CapacityError(
                    RejectReason.OVER_CAPACITY,
                    f"open alert cap {self._max_open} reached",
                )
            self._alerts[alert.alert_id] = alert

    def get(self, alert_id: str) -> Alert | None:
        with self._lock:
            return self._alerts.get(alert_id)

    def update(self, alert: Alert) -> None:
        with self._lock:
            self._alerts[alert.alert_id] = alert

    def find_open(self, fingerprint: str) -> Alert | None:
        """Open alert with the same dedupe fingerprint."""
        with self._lock:
            for alert in self._alerts.values():
                if alert.status == AlertStatus.OPEN and alert.fingerprint == fingerprint:
                    return alert
        return None

    def find_active_suppressor(self, suppress_key: str) -> Alert | None:
        """Any open alert carrying the same suppression key."""
        with self._lock:
            for alert in self._alerts.values():
                if alert.status == AlertStatus.OPEN and alert.suppress_key == suppress_key:
                    return alert
        return None

    def all(self) -> list[Alert]:
        with self._lock:
            return list(self._alerts.values())

    def _open_count_locked(self) -> int:
        return sum(1 for a in self._alerts.values() if a.status == AlertStatus.OPEN)


class DecisionJournal:
    """Append-only, in-memory decision log with a monotonic sequence."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._items: list[Decision] = []

    def append(self, decision: Decision) -> Decision:
        with self._lock:
            stored = dataclasses.replace(decision, seq=len(self._items) + 1)
            self._items.append(stored)
            return stored

    def all(self) -> list[Decision]:
        with self._lock:
            return list(self._items)

    def reset(self) -> None:
        with self._lock:
            self._items.clear()
