"""Deterministic replay of stored events.

Replay never touches live alert state. Events are processed in their original
ingestion order. For every event, the set of rules to evaluate is the union of
(a) rules that produced a journal decision for the event, pinned to the exact
revision recorded in that decision, and (b) the currently active ruleset (so
replay reflects what a first-time evaluation would see today when no history
exists). Each replayed decision is then compared with its original journal
decision: rule revision, signature, match flag and alert outcome.
"""

from __future__ import annotations

from detection.config import EngineConfig
from detection.engine import DetectionEngine
from detection.models import Decision, NormalizedEvent, Rule
from detection.store import AlertStore, DecisionJournal, EventStore, RuleStore


class _PinnedRuleStore(RuleStore):
    """Read-only rule store presenting a frozen, per-event ruleset view."""

    def __init__(self) -> None:
        super().__init__()
        self._pin: dict[tuple[str, int], Rule] = {}

    def install_history(self, history_store: RuleStore) -> None:
        # RuleStore keeps all revisions; copy references out for replay.
        for (_id, rev), rule in list(history_store._history.items()):
            self._pin[(_id, rev)] = rule
            self.put(rule)

    def pin_for_event(self, revisions: dict[str, int]) -> None:
        active: dict[str, Rule] = {}
        for rule_id, revision in revisions.items():
            rule = self._pin.get((rule_id, revision))
            if rule is not None:
                active[rule_id] = rule
        self._rules = active


def replay(
    *,
    events: list[NormalizedEvent],
    rules: RuleStore,
    original: list[Decision],
    cfg: EngineConfig,
) -> dict:
    replay_events = EventStore(capacity=max(len(events) + 1, 1))
    replay_events.add_batch(events)
    replay_alerts = AlertStore(max_open_alerts=cfg.max_open_alerts)
    pinned = _PinnedRuleStore()
    pinned.install_history(rules)
    engine = DetectionEngine(
        pinned, replay_alerts, replay_events, DecisionJournal(), cfg=cfg)

    by_event: dict[str, list[Decision]] = {}
    for d in original:
        by_event.setdefault(d.event_id, []).append(d)

    replay_inputs = sorted(events, key=lambda e: e.ingested_at)
    replayed: list[Decision] = []
    missing_rules: list[str] = []
    for event in replay_inputs:
        prior = by_event.get(event.event_id, [])
        revisions = {d.rule_id: d.rule_revision for d in prior}
        if prior:
            pinned.pin_for_event(revisions)
            for rule_id, rev in revisions.items():
                if pinned.get_revision(rule_id, rev) is None:
                    missing_rules.append(f"{rule_id}@r{rev}")
        else:
            pinned._rules = rules.snapshot()
        _, decisions = engine.evaluate(event, now=event.ingested_at)
        replayed.extend(decisions)

    original_sorted = sorted(original, key=lambda d: d.seq)
    mismatches: list[dict] = []
    for old, new in zip(original_sorted, replayed):
        if (
            old.event_id != new.event_id
            or old.rule_id != new.rule_id
            or old.rule_revision != new.rule_revision
            or old.rule_signature != new.rule_signature
            or old.matched != new.matched
            or (old.alert_id is None) != (new.alert_id is None)
        ):
            mismatches.append({
                "seq": old.seq,
                "event_id": old.event_id,
                "rule_id": old.rule_id,
                "original": _brief(old),
                "replayed": _brief(new),
            })
    if len(original_sorted) != len(replayed):
        mismatches.append({
            "seq": None,
            "event_id": None,
            "rule_id": None,
            "original": f"{len(original_sorted)} decisions",
            "replayed": f"{len(replayed)} decisions",
        })

    return {
        "events_replayed": len(events),
        "decisions_original": len(original_sorted),
        "decisions_replayed": len(replayed),
        "alerts_replayed": len(replay_alerts.all()),
        "missing_rule_revisions": sorted(set(missing_rules)),
        "consistent": not mismatches and not missing_rules,
        "mismatches": mismatches,
        "decisions": [_decision_brief(d) for d in replayed],
    }


def _decision_brief(d: Decision) -> dict:
    return {
        "seq": d.seq,
        "event_id": d.event_id,
        "input_digest": d.input_digest[:16],
        "rule_id": d.rule_id,
        "rule_revision": d.rule_revision,
        "rule_signature": d.rule_signature[:12],
        "matched": d.matched,
        "alert_id": d.alert_id,
        "reason": d.reason,
    }


def _brief(d: Decision) -> str:
    return (f"event={d.event_id} rule={d.rule_id}@r{d.rule_revision} "
            f"matched={d.matched} alert={d.alert_id}")
