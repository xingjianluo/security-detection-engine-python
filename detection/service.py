"""Application facade wiring stores, engine, journal and concurrency.

Concurrency model
-----------------
A single reentrant lock serializes the mutating sections of ingestion, rule
reload, alert transition and replay setup. Reads (list/query) take the same
lock for a consistent point-in-time view. Rule reloads swap the active ruleset
atomically; an in-flight event always sees exactly one full ruleset snapshot.

Failure hygiene
---------------
Detection runs per accepted event after the event batch has committed. Events
are only evaluated when their store commit succeeded, and journal appends for
an event are durable before the next event starts. There is no cross-resource
partial state: normalization failure only marks that item rejected.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import threading
import time

from detection.alerts import transition
from detection.config import EngineConfig
from detection.engine import DetectionEngine
from detection.errors import (
    AlertTransitionError,
    DetectionError,
    RejectReason,
)
from detection.ingestion import ingest_batch
from detection.journal import PersistentJournal
from detection.models import (
    Alert,
    AlertStatus,
    IngestResult,
    NormalizedEvent,
    RuleFormatVersion,
    SourceType,
)
from detection.replay import replay as run_replay
from detection.rules import load_rules_file
from detection.store import AlertStore, DecisionJournal, EventStore, RuleStore

log = logging.getLogger("detection")


def _rule_to_dict(rule) -> dict:
    return {
        "rule_id": rule.rule_id,
        "version": rule.version.value,
        "revision": rule.rule_revision,
        "name": rule.name,
        "severity": rule.severity.value,
        "condition": {
            "field": rule.condition.field,
            "op": rule.condition.op.value,
            "value": rule.condition.value,
        },
        "dedupe_window_seconds": rule.dedupe_window_seconds,
        "suppress_key": rule.suppress_key,
        "suppress_severity_ceiling": (
            rule.suppress_severity_ceiling.value
            if rule.suppress_severity_ceiling else None),
        "signature": rule.signature[:12],
    }


def _alert_to_dict(alert: Alert) -> dict:
    return dataclasses.asdict(alert) | {
        "status": alert.status.value,
        "severity": alert.severity.value,
        "rule_version": alert.rule_version.value,
    }


class DetectionService:
    def __init__(self, *, cfg: EngineConfig | None = None) -> None:
        self.cfg = cfg or EngineConfig()
        os.makedirs(self.cfg.data_dir, exist_ok=True)
        self._lock = threading.RLock()
        self.events = EventStore(capacity=self.cfg.max_events_in_memory)
        self.rules = RuleStore()
        self.alerts = AlertStore(max_open_alerts=self.cfg.max_open_alerts)
        self.journal = DecisionJournal()
        self.engine = DetectionEngine(
            self.rules, self.alerts, self.events, self.journal,
            cfg=self.cfg, lock=self._lock,
        )
        journal_path = os.path.join(self.cfg.data_dir, self.cfg.journal_file)
        self.file_journal = PersistentJournal(journal_path)
        self._rules_path = os.path.join(self.cfg.data_dir, self.cfg.rules_file)
        self._snapshot_path = os.path.join(self.cfg.data_dir, self.cfg.snapshot_file)
        self._rules_reload_generation = 0
        if os.path.exists(self._rules_path):
            try:
                self.reload_rules()
            except DetectionError as exc:
                log.warning("initial rules load failed: %s", exc)

    # ------------------------------------------------------------------ #
    # Ingestion
    # ------------------------------------------------------------------ #
    def ingest(
        self,
        raw_events: list[object],
        source: SourceType,
        *,
        now: float | None = None,
    ) -> IngestResult:
        now = time.time() if now is None else now
        with self._lock:
            result = ingest_batch(raw_events, source, self.events, now=now, cfg=self.cfg)
            for event in result.accepted:
                _, decisions = self.engine.evaluate(event, now=now)
                for decision in decisions:
                    stored = self.journal.append(decision)
                    self.file_journal.append(stored)
                self._log_event_summary(event, decisions)
            return result

    def _log_event_summary(self, event: NormalizedEvent, decisions) -> None:
        digest = event.input_digest()[:12]
        for d in decisions:
            log.info(
                "event %s src=%s sev=%s digest=%s | rule=%s@r%s sig=%s matched=%s "
                "alert=%s | %s",
                event.event_id, event.source.value, event.severity.value, digest,
                d.rule_id, d.rule_revision, d.rule_signature[:10], d.matched,
                d.alert_id or "-", d.reason,
            )

    # ------------------------------------------------------------------ #
    # Rules
    # ------------------------------------------------------------------ #
    def reload_rules(self, *, assumed_version: RuleFormatVersion | None = None) -> list[str]:
        with self._lock:
            before = self.rules.snapshot()
            rules = load_rules_file(
                self._rules_path, self.rules, cfg=self.cfg,
                assumed_version=assumed_version,
            )
            self._rules_reload_generation += 1
            ids = [r.rule_id for r in rules]
            log.info("rules reloaded gen=%d ids=%s (was %s)",
                     self._rules_reload_generation, ids, list(before))
            return ids

    def list_rules(self) -> list[dict]:
        with self._lock:
            return [_rule_to_dict(r) for r in self.rules.all()]

    # ------------------------------------------------------------------ #
    # Alerts
    # ------------------------------------------------------------------ #
    def list_alerts(self) -> list[dict]:
        with self._lock:
            return [_alert_to_dict(a) for a in self.alerts.all()]

    def get_alert(self, alert_id: str) -> dict:
        with self._lock:
            alert = self.alerts.get(alert_id)
            if alert is None:
                raise AlertTransitionError(RejectReason.ALERT_NOT_FOUND,
                                           f"no alert {alert_id}")
            return _alert_to_dict(alert)

    def transition_alert(self, alert_id: str, target: str) -> dict:
        with self._lock:
            alert = self.alerts.get(alert_id)
            if alert is None:
                raise AlertTransitionError(RejectReason.ALERT_NOT_FOUND,
                                           f"no alert {alert_id}")
            try:
                new_status = AlertStatus(target)
            except ValueError:
                raise AlertTransitionError(
                    RejectReason.ILLEGAL_TRANSITION, f"unknown target status {target!r}")
            updated = transition(alert, new_status, now=time.time())
            self.alerts.update(updated)
            log.info("alert %s %s -> %s", alert_id, alert.status.value, new_status.value)
            return _alert_to_dict(updated)

    def merge_alerts(self, parent_id: str, child_id: str) -> dict:
        """Explicitly merge child into parent (child becomes MERGED)."""
        with self._lock:
            parent = self.alerts.get(parent_id)
            child = self.alerts.get(child_id)
            if parent is None or child is None:
                raise AlertTransitionError(
                    RejectReason.ALERT_NOT_FOUND,
                    f"parent or child missing: {parent_id}/{child_id}")
            merged = transition(child, AlertStatus.MERGED, now=time.time())
            merged.parent_alert_id = parent.alert_id
            parent.event_count += child.event_count
            parent.event_ids.extend(child.event_ids)
            self.alerts.update(merged)
            self.alerts.update(parent)
            return _alert_to_dict(merged)

    # ------------------------------------------------------------------ #
    # Snapshot & replay
    # ------------------------------------------------------------------ #
    def save_snapshot(self) -> str:
        with self._lock:
            payload = {
                "taken_at": time.time(),
                "events": [
                    dataclasses.asdict(e) | {"source": e.source.value,
                                             "severity": e.severity.value}
                    for e in self.events.all()
                ],
                "alerts": [_alert_to_dict(a) for a in self.alerts.all()],
                "rules_generation": self._rules_reload_generation,
            }
            tmp_path = self._snapshot_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self._snapshot_path)
            return self._snapshot_path

    def replay(self) -> dict:
        with self._lock:
            events = self.events.all()
            original = self.journal.all()
            return run_replay(
                events=events, rules=self.rules, original=original, cfg=self.cfg)

    def health(self) -> dict:
        with self._lock:
            return {
                "status": "ok",
                "events": self.events.count(),
                "rules": len(self.rules.all()),
                "alerts": len(self.alerts.all()),
                "decisions": len(self.journal.all()),
                "rules_generation": self._rules_reload_generation,
                "limits": {
                    "max_event_bytes": self.cfg.max_event_bytes,
                    "max_batch_events": self.cfg.max_batch_events,
                    "max_batch_bytes": self.cfg.max_batch_bytes,
                    "max_events_in_memory": self.cfg.max_events_in_memory,
                    "max_open_alerts": self.cfg.max_open_alerts,
                },
            }

    def close(self) -> None:
        with self._lock:
            self.file_journal.close()
