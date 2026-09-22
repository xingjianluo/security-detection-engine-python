"""线程安全的本地存储。

单一 ``threading.RLock`` 串行化全部写操作；读操作返回深拷贝快照，
调用方遍历/修改返回值不会影响内部状态。规则版本以 append-only 方式
保留全部历史 revision，使历史告警可按其命中时的规则版本复现。
"""

from __future__ import annotations

import threading
from copy import deepcopy
from datetime import datetime, timezone

from .models import Alert, AlertState, Event, JournalEntry, Rule, Severity


def _dt(raw) -> datetime:
    if isinstance(raw, datetime):
        return raw
    return datetime.fromisoformat(raw)


class Store:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._events: dict[str, Event] = {}
        self._alerts: dict[str, Alert] = {}
        # revision -> list[Rule]（规则集历史，只增不改）
        self._rule_history: dict[int, list[Rule]] = {}
        self._revision = 0
        self._journal: list[JournalEntry] = []
        self._seq = 0

    # ---- 幂等事件摄入 ----
    def seen_event(self, event_id: str) -> bool:
        with self._lock:
            return event_id in self._events

    def put_event_if_absent(self, event: Event) -> bool:
        """原子写入；已存在返回 False。重复并发投递只有一个胜出。"""
        with self._lock:
            if event.event_id in self._events:
                return False
            self._events[event.event_id] = event
            return True

    def event_count(self) -> int:
        with self._lock:
            return len(self._events)

    def get_event(self, event_id: str) -> Event | None:
        with self._lock:
            event = self._events.get(event_id)
            return deepcopy(event) if event else None

    # ---- 规则版本 ----
    def publish_rules(self, revision: int, rules: list[Rule]) -> None:
        with self._lock:
            if revision in self._rule_history:
                # 相同内容幂等重放允许；不同内容拒绝以防覆盖历史
                existing = [r.rule_id for r in self._rule_history[revision]]
                incoming = [r.rule_id for r in rules]
                if existing != incoming:
                    raise ValueError(
                        f"rule revision {revision} already exists with different content"
                    )
                return
            self._rule_history[revision] = list(rules)
            self._revision = max(self._revision, revision)

    def active_rules(self) -> list[Rule]:
        with self._lock:
            if not self._rule_history:
                return []
            return list(self._rule_history[self._revision])

    def rules_at(self, revision: int) -> list[Rule] | None:
        with self._lock:
            rules = self._rule_history.get(revision)
            return list(rules) if rules is not None else None

    def current_revision(self) -> int:
        with self._lock:
            return self._revision

    def rule_revisions(self) -> list[int]:
        with self._lock:
            return sorted(self._rule_history)

    # ---- 告警 ----
    def put_alert(self, alert: Alert) -> None:
        with self._lock:
            self._alerts[alert.alert_id] = deepcopy(alert)

    def update_alert(self, alert: Alert) -> None:
        with self._lock:
            self._alerts[alert.alert_id] = deepcopy(alert)

    def get_alert(self, alert_id: str) -> Alert | None:
        with self._lock:
            alert = self._alerts.get(alert_id)
            return deepcopy(alert) if alert else None

    def open_alert_by_keys(self, merge_key: str, correlation_key: str) -> Alert | None:
        """查找仍在活动状态（未 RESOLVED/MERGED）且键匹配的主告警。"""
        with self._lock:
            for alert in self._alerts.values():
                if alert.state.is_terminal:
                    continue
                if alert.state == AlertState.SUPPRESSED:
                    # 抑制中的告警仍参与去重/合并归属判定
                    pass
                if alert.merge_key == merge_key and alert.correlation_key == correlation_key:
                    return deepcopy(alert)
            return None

    def active_suppressors(self, at: datetime) -> list[Alert]:
        """返回此刻处于抑制窗口内的非终态主告警（按严重度降序）。"""
        with self._lock:
            result = []
            for alert in self._alerts.values():
                if alert.state.is_terminal or alert.suppressed_by:
                    continue
                rule = None  # 抑制窗口参数存在 alert.trace 中
                window_s = alert.trace.get("suppress_window_s", 0)
                max_sev = alert.trace.get("suppress_max_severity")
                if window_s <= 0:
                    continue
                delta = (at - alert.last_occurred_at).total_seconds()
                if 0 <= delta < window_s:
                    result.append(deepcopy(alert))
            result.sort(key=lambda a: a.severity.rank, reverse=True)
            return result

    def all_alerts(self) -> list[Alert]:
        with self._lock:
            return [deepcopy(a) for a in self._alerts.values()]

    # ---- 流水 ----
    def append_journal(self, entry: JournalEntry) -> None:
        with self._lock:
            self._journal.append(entry)

    def next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def journal(self) -> list[JournalEntry]:
        with self._lock:
            return list(self._journal)

    def journal_len(self) -> int:
        with self._lock:
            return len(self._journal)

    # ---- 快照（原子导出/恢复） ----
    def snapshot(self) -> dict:
        with self._lock:
            return {
                "events": {k: v.to_dict() for k, v in self._events.items()},
                "alerts": {k: v.to_dict() for k, v in self._alerts.items()},
                "rule_history": {
                    rev: [
                        {
                            "rule_id": r.rule_id,
                            "version": r.version,
                            "revision": r.revision,
                            "name": r.name,
                            "event_type": r.event_type,
                            "conditions": r.conditions,
                            "severity": r.severity.value,
                            "dedup_window_s": r.dedup_window_s,
                            "suppress_window_s": r.suppress_window_s,
                            "suppress_max_severity": (
                                r.suppress_max_severity.value
                                if r.suppress_max_severity else None
                            ),
                            "correlation_key": r.correlation_key,
                            "merge_key": r.merge_key,
                            "enabled": r.enabled,
                        }
                        for r in rules
                    ]
                    for rev, rules in self._rule_history.items()
                },
                "revision": self._revision,
                "seq": self._seq,
            }

    def restore(self, data: dict) -> None:
        with self._lock:
            events: dict[str, Event] = {}
            for raw in data.get("events", {}).values():
                events[raw["event_id"]] = Event(
                    event_id=raw["event_id"],
                    source=raw["source"],
                    event_type=raw["event_type"],
                    severity=Severity(raw["severity"]),
                    occurred_at=_dt(raw["occurred_at"]),
                    ingested_at=_dt(raw["ingested_at"]),
                    src_ip=raw.get("src_ip"),
                    dst_ip=raw.get("dst_ip"),
                    user=raw.get("user"),
                    host=raw.get("host"),
                    action=raw.get("action"),
                    raw=raw.get("raw", {}),
                    digest=raw.get("digest", ""),
                )
            alerts: dict[str, Alert] = {}
            for raw in data.get("alerts", {}).values():
                alerts[raw["alert_id"]] = Alert(
                    alert_id=raw["alert_id"],
                    rule_id=raw["rule_id"],
                    rule_version=raw["rule_version"],
                    rule_revision=raw["rule_revision"],
                    correlation_key=raw["correlation_key"],
                    merge_key=raw["merge_key"],
                    severity=Severity(raw["severity"]),
                    state=AlertState(raw["state"]),
                    first_event_id=raw["first_event_id"],
                    last_event_id=raw["last_event_id"],
                    first_occurred_at=_dt(raw["first_occurred_at"]),
                    last_occurred_at=_dt(raw["last_occurred_at"]),
                    created_at=_dt(raw["created_at"]),
                    updated_at=_dt(raw["updated_at"]),
                    event_count=raw.get("event_count", 1),
                    merged_into=raw.get("merged_into"),
                    suppressed_by=raw.get("suppressed_by"),
                    event_digests=list(raw.get("event_digests", [])),
                    trace=dict(raw.get("trace", {})),
                )
            history: dict[int, list[Rule]] = {}
            for rev_s, raws in data.get("rule_history", {}).items():
                history[int(rev_s)] = [
                    Rule(
                        rule_id=r["rule_id"],
                        version=r["version"],
                        revision=int(rev_s),
                        name=r["name"],
                        event_type=r["event_type"],
                        conditions=r["conditions"],
                        severity=Severity(r["severity"]),
                        dedup_window_s=r["dedup_window_s"],
                        suppress_window_s=r.get("suppress_window_s", 0),
                        suppress_max_severity=(
                            Severity(r["suppress_max_severity"])
                            if r.get("suppress_max_severity") else None
                        ),
                        correlation_key=r.get("correlation_key", []),
                        merge_key=r.get("merge_key", []),
                        enabled=r.get("enabled", True),
                    )
                    for r in raws
                ]
            self._events = events
            self._alerts = alerts
            self._rule_history = history
            self._revision = int(data.get("revision", 0))
            self._seq = int(data.get("seq", 0))
            self._journal = []
