"""Rule evaluation, fingerprinting, dedupe windows and suppression.

One :meth:`DetectionEngine.evaluate` call takes a ruleset snapshot and runs a
single normalized event through every rule. For each matched rule, in order:

1. **Suppress** — if the rule declares ``suppress_key`` and an OPEN alert with
   the same key is already active, and the new event is *not more severe* than
   the suppressor's declared ceiling, a child alert is created in the
   ``suppressed`` state carrying ``parent_alert_id``. A higher-severity event
   is never swallowed: it produces a normal OPEN alert.
2. **Dedupe** — the fingerprint is ``rule_id:revision:field-values``. If an
   OPEN alert with the same fingerprint exists and ``now`` is still inside its
   window, the event is folded into it (count incremented). Events arriving
   after the window boundary create a new alert; late events inside an open
   window still fold deterministically.
3. **Create** — otherwise a new OPEN alert is created.

Every judgement (match or not) is appended to the decision journal with the
rule revision + signature that produced it.
"""

from __future__ import annotations

import hashlib
import re
import threading
import uuid

from detection.config import EngineConfig
from detection.models import (
    Alert,
    AlertStatus,
    Decision,
    NormalizedEvent,
    Rule,
    RuleCondition,
)
from detection.store import AlertStore, DecisionJournal, EventStore, RuleStore


def resolve_field(field: str, event: NormalizedEvent) -> object:
    """Resolve ``event_type`` / ``severity`` / ``src_ip`` / ``target`` or a
    dotted ``fields.<key>`` lookup."""
    top = {
        "event_type": event.event_type,
        "severity": event.severity.value,
        "src_ip": event.source_ip,
        "source_ip": event.source_ip,
        "target": event.target,
        "event_id": event.event_id,
    }
    if field in top:
        return top[field]
    if field.startswith("fields."):
        return event.fields.get(field[len("fields."):])
    if field == "fields":
        return event.fields
    return event.fields.get(field)


def _compare(condition: RuleCondition, actual: object) -> bool:
    op, expected = condition.op, condition.value
    if op == op.EQ:
        return actual == expected
    if op == op.NEQ:
        return actual != expected
    if op == op.CONTAINS:
        if isinstance(actual, str):
            return expected in actual
        if isinstance(actual, (list, tuple, set, dict)):
            return expected in actual
        return False
    if actual is None or isinstance(actual, bool) or not isinstance(actual, (int, float)):
        return False
    if op == op.GT:
        return actual > expected
    if op == op.GTE:
        return actual >= expected
    if op == op.LT:
        return actual < expected
    if op == op.LTE:
        return actual <= expected
    if op == op.REGEX:
        return isinstance(actual, str) and re.search(str(expected), actual) is not None
    return False


def fingerprint(rule: Rule, event: NormalizedEvent) -> str:
    basis = repr((
        rule.rule_id,
        rule.rule_revision,
        rule.condition.field,
        resolve_field(rule.condition.field, event),
    )).encode()
    return hashlib.sha256(basis).hexdigest()[:32]


class DetectionEngine:
    def __init__(
        self,
        rules: RuleStore,
        alerts: AlertStore,
        events: EventStore,
        journal: DecisionJournal,
        *,
        cfg: EngineConfig,
        lock: threading.RLock | None = None,
    ) -> None:
        self.rules = rules
        self.alerts = alerts
        self.events = events
        self.journal = journal
        self.cfg = cfg
        self._lock = lock or threading.RLock()

    # ------------------------------------------------------------------ #
    def _make_decision(
        self, *, event: NormalizedEvent, rule: Rule, matched: bool,
        reason: str, alert_id: str | None, now: float,
    ) -> Decision:
        return Decision(
            seq=0,
            event_id=event.event_id,
            input_digest=event.input_digest(),
            rule_id=rule.rule_id,
            rule_revision=rule.rule_revision,
            rule_signature=rule.signature,
            matched=matched,
            reason=reason,
            alert_id=alert_id,
            at=now,
        )

    def _fold_into_open_alert(self, alert: Alert, event: NormalizedEvent, now: float) -> None:
        alert.event_count += 1
        alert.last_event_id = event.event_id
        alert.event_ids.append(event.event_id)
        alert.updated_at = now
        self.alerts.update(alert)

    def _new_alert(self, rule: Rule, event: NormalizedEvent, fp: str,
                   now: float, *, status: AlertStatus,
                   parent: Alert | None) -> Alert:
        alert = Alert(
            alert_id=f"al-{uuid.uuid4().hex[:16]}",
            rule_id=rule.rule_id,
            rule_revision=rule.rule_revision,
            rule_version=rule.version,
            rule_signature=rule.signature,
            fingerprint=fp,
            severity=max((rule.severity, event.severity), key=lambda s: s.rank)
                     if parent is None else rule.severity,
            status=status,
            first_event_id=event.event_id,
            last_event_id=event.event_id,
            event_count=1,
            opened_at=now,
            updated_at=now,
            suppress_key=rule.suppress_key,
            parent_alert_id=parent.alert_id if parent is not None else None,
            event_ids=[event.event_id],
        )
        self.alerts.add(alert)
        return alert

    def evaluate(
        self, event: NormalizedEvent, *, now: float
    ) -> tuple[list[Alert], list[Decision]]:
        """Evaluate one event against a point-in-time ruleset snapshot.

        Returns ``(new_or_folded_alerts, decisions)``. Callers own journal
        persistence (the engine itself does not append), which keeps replay
        and live execution on the same code path.
        """
        outcomes: list[Alert] = []
        decisions: list[Decision] = []
        ruleset = self.rules.snapshot()  # point-in-time; reloads can't race us
        for rule in ruleset.values():
            actual = resolve_field(rule.condition.field, event)
            matched = _compare(rule.condition, actual)
            if not matched:
                decisions.append(self._make_decision(
                    event=event, rule=rule, matched=False,
                    reason=f"field {rule.condition.field!r}={actual!r} "
                           f"failed {rule.condition.op.value} {rule.condition.value!r}",
                    alert_id=None, now=now))
                continue

            fp = fingerprint(rule, event)

            # 1) suppression (v2 feature, bound by severity ceiling) -------
            if rule.suppress_key is not None:
                suppressor = self.alerts.find_active_suppressor(rule.suppress_key)
                # Only cross-fingerprint matches are candidates for
                # suppression; the same fingerprint goes through dedupe.
                if suppressor is not None and suppressor.fingerprint != fp:
                    ceilings = [c for c in (
                        rule.suppress_severity_ceiling,
                        (lambda r: r.suppress_severity_ceiling if r else None)(
                            self.rules.get(suppressor.rule_id)),
                    ) if c is not None]
                    # Take the strictest ceiling: a low-priority suppressor
                    # can never swallow an alert above its own ceiling.
                    ceiling = min(ceilings, key=lambda s: s.rank) if ceilings else None
                    if ceiling is not None and event.severity.rank <= ceiling.rank:
                        child = self._new_alert(
                            rule, event, fp, now,
                            status=AlertStatus.SUPPRESSED, parent=suppressor,
                        )
                        decisions.append(self._make_decision(
                            event=event, rule=rule, matched=True,
                            reason=f"suppressed by {suppressor.alert_id} "
                                   f"(ceiling {ceiling.value})",
                            alert_id=child.alert_id, now=now))
                        outcomes.append(child)
                        continue
                    # Higher severity: suppression must not swallow it.

            # 2) dedupe window ---------------------------------------------
            open_alert = self.alerts.find_open(fp)
            if open_alert is not None:
                window = rule.dedupe_window_seconds or self.cfg.default_dedupe_window_seconds
                # Window starts at the first event's wall-clock ingestion time;
                # an event arriving after the boundary starts a fresh alert,
                # regardless of its own (possibly late) event timestamp.
                if now <= open_alert.opened_at + window:
                    self._fold_into_open_alert(open_alert, event, now)
                    decisions.append(self._make_decision(
                        event=event, rule=rule, matched=True,
                        reason=f"dedupe folded into {open_alert.alert_id} "
                               f"(count={open_alert.event_count})",
                        alert_id=open_alert.alert_id, now=now))
                    continue
                # boundary crossed -> fall through and open a new alert

            # 3) create ----------------------------------------------------
            alert = self._new_alert(rule, event, fp, now,
                                    status=AlertStatus.OPEN, parent=None)
            decisions.append(self._make_decision(
                event=event, rule=rule, matched=True,
                reason=f"opened alert {alert.alert_id}",
                alert_id=alert.alert_id, now=now))
            outcomes.append(alert)
        return outcomes, decisions
