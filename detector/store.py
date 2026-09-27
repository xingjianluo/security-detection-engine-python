"""线程安全的本地存储。

单一 ``threading.RLock`` 串行化全部写操作；读操作返回深拷贝快照，
调用方遍历/修改返回值不会影响内部状态。规则版本以 append-only 方式
保留全部历史 revision，使历史告警可按其命中时的规则版本复现。

有界保留
========
- ``_seen`` 为幂等锚点（event_id -> digest），**永不淘汰**：即使事件
  明细已被淘汰出本地保留，重复投递仍然判定为已处理；
- 事件明细（``_events``）、已终态告警明细、流水明细可按最旧顺序淘汰；
- 活动（非终态）告警是去重/合并/抑制的锚点，**永不淘汰**，因此淘汰
  不会造成计数漂移、去重失效或抑制结论变化。
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from copy import deepcopy
from datetime import datetime, timezone

from .models import Alert, AlertState, Event, JournalEntry, Rule, Severity


def _dt(raw) -> datetime:
    if isinstance(raw, datetime):
        return raw
    return datetime.fromisoformat(raw)


def _row_bytes(payload: dict) -> int:
    return len(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"))


@dataclass(frozen=True)
class EvictedItem:
    """一条被淘汰出本地保留的历史明细。"""

    kind: str            # "event" | "alert"
    key: str             # event_id / alert_id
    seq: int             # 该明细在流水中的锚点 seq（无则为 0）
    detail: dict         # 明细快照（归档用）


class Store:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        # 幂等锚点：event_id -> digest，永不淘汰
        self._seen: dict[str, str] = {}
        self._events: dict[str, Event] = {}
        self._event_seq: dict[str, int] = {}
        self._event_bytes: dict[str, int] = {}
        self._alerts: dict[str, Alert] = {}
        # 终态告警最近一次变更 seq（淘汰排序锚点）
        self._alert_seq: dict[str, int] = {}
        self._terminal_bytes: dict[str, int] = {}
        # revision -> list[Rule]（规则集历史，只增不改）
        self._rule_history: dict[int, list[Rule]] = {}
        self._revision = 0
        self._journal: list[JournalEntry] = []
        self._journal_bytes: dict[int, int] = {}
        # 已交给归档、等待 ack 后物理裁剪的流水水位：这部分明细不再占用
        # 本地保留容量（它的长期留存已由归档承接）。
        self._archive_pending_watermark = 0
        self._seq = 0

    # ---- 幂等事件摄入 ----
    def seen_event(self, event_id: str) -> bool:
        with self._lock:
            return event_id in self._seen

    def put_event_if_absent(self, event: Event) -> bool:
        """原子写入；已存在（哪怕明细已淘汰）返回 False。

        重复并发投递只有一个胜出；锚点与明细分离后，淘汰历史明细不影响
        重复投递判定。
        """
        with self._lock:
            if event.event_id in self._seen:
                return False
            self._seen[event.event_id] = event.digest
            self._events[event.event_id] = event
            self._event_bytes[event.event_id] = _row_bytes(event.to_dict())
            return True

    def bind_event_seq(self, event_id: str, seq: int) -> None:
        """记录事件被接受时的流水 seq（淘汰排序/水位用）。"""
        with self._lock:
            self._event_seq[event_id] = seq

    def seen_count(self) -> int:
        with self._lock:
            return len(self._seen)

    def event_count(self) -> int:
        with self._lock:
            return len(self._seen)

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
            self._index_alert_bytes(alert)

    def update_alert(self, alert: Alert) -> None:
        with self._lock:
            self._alerts[alert.alert_id] = deepcopy(alert)
            self._index_alert_bytes(alert)

    def bind_alert_seq(self, alert_id: str, seq: int) -> None:
        """终态告警最近一次状态变更 seq（淘汰排序锚点）。"""
        with self._lock:
            if seq > self._alert_seq.get(alert_id, 0):
                self._alert_seq[alert_id] = seq

    def _index_alert_bytes(self, alert: Alert) -> None:
        """只有终态告警的明细计入可淘汰账本；活动告警是锚点，不计。"""
        if alert.state.is_terminal:
            self._terminal_bytes[alert.alert_id] = _row_bytes(alert.to_dict())
        else:
            self._terminal_bytes.pop(alert.alert_id, None)
            self._alert_seq.pop(alert.alert_id, None)

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
            self._journal_bytes[entry.seq] = _row_bytes(
                {"seq": entry.seq, "kind": entry.kind, "payload": entry.payload})

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

    def current_journal_max_seq(self) -> int:
        """当前内存流水（含待归档前缀）中的最大 seq；无流水返回 0。"""
        with self._lock:
            return self._journal[-1].seq if self._journal else 0

    def journal_rows_up_to(self, watermark_seq: int) -> list[JournalEntry]:
        with self._lock:
            return [e for e in self._journal if e.seq <= watermark_seq]

    def mark_archive_pending(self, watermark_seq: int) -> None:
        """把已交归档的流水前缀从容量账中移除（物理裁剪待 ack）。"""
        with self._lock:
            if watermark_seq > self._archive_pending_watermark:
                self._archive_pending_watermark = watermark_seq

    def trim_journal(self, watermark_seq: int, *,
                     next_pending_watermark: int = 0) -> None:
        """归档提交后丢弃 ``seq <= watermark`` 的流水明细。

        ``next_pending_watermark``：物理裁剪后仍在排队（已交归档但尚未
        提交）的更高水位，容量账仍排除该连续前缀。
        """
        with self._lock:
            kept = [e for e in self._journal if e.seq > watermark_seq]
            self._journal = kept
            for sq in [s for s in self._journal_bytes if s <= watermark_seq]:
                del self._journal_bytes[sq]
            self._archive_pending_watermark = max(0, next_pending_watermark)

    # ---- 有界保留：容量账与最旧淘汰 ----
    def _journal_rows_live(self):
        wm = self._archive_pending_watermark
        return [e for e in self._journal if e.seq > wm]

    def retained_count(self) -> int:
        with self._lock:
            return (len(self._events) + len(self._terminal_bytes)
                    + len(self._journal_rows_live()))

    def retained_bytes(self) -> int:
        with self._lock:
            wm = self._archive_pending_watermark
            jb = sum(b for s, b in self._journal_bytes.items() if s > wm)
            return (sum(self._event_bytes.values())
                    + sum(self._terminal_bytes.values()) + jb)

    def oldest_evictable(self) -> EvictedItem | None:
        """返回当前最旧的可淘汰明细（事件明细 / 已终态告警明细）。

        活动（非终态）告警永不淘汰；幂等锚点永不淘汰。
        """
        with self._lock:
            candidates: list[tuple[int, str, str, dict]] = []
            for eid, event in self._events.items():
                candidates.append((
                    self._event_seq.get(eid, 0), "event", eid, event.to_dict()))
            for aid, size in self._terminal_bytes.items():
                alert = self._alerts.get(aid)
                if alert is None:
                    continue
                candidates.append((
                    self._alert_seq.get(aid, 0), "alert", aid, alert.to_dict()))
            if not candidates:
                return None
            seq, kind, key, detail = min(candidates, key=lambda c: (c[0], c[2]))
            return EvictedItem(kind=kind, key=key, seq=seq, detail=detail)

    def remove_evicted(self, item: EvictedItem) -> None:
        """实际移除一条已确认归档的明细；锚点与活动状态不动。"""
        with self._lock:
            if item.kind == "event":
                self._events.pop(item.key, None)
                self._event_bytes.pop(item.key, None)
                self._event_seq.pop(item.key, None)
                # 注意：self._seen 锚点保留，重复投递仍判重
            elif item.kind == "alert":
                alert = self._alerts.get(item.key)
                if alert is not None and alert.state.is_terminal:
                    del self._alerts[item.key]
                    self._terminal_bytes.pop(item.key, None)
                    self._alert_seq.pop(item.key, None)

    # ---- 快照（原子导出/恢复） ----
    def snapshot(self) -> dict:
        with self._lock:
            return {
                "seen": dict(self._seen),
                "events": {k: v.to_dict() for k, v in self._events.items()},
                "event_seq": dict(self._event_seq),
                "alert_seq": dict(self._alert_seq),
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
            for eid, raw in data.get("events", {}).items():
                self._event_bytes[eid] = _row_bytes(raw)
            self._alerts = alerts
            for alert in alerts.values():
                self._index_alert_bytes(alert)
            self._rule_history = history
            self._revision = int(data.get("revision", 0))
            self._seq = int(data.get("seq", 0))
            self._journal = []
            self._journal_bytes = {}
            # 幂等锚点：新版本快照直接给出；旧快照（无 seen）从事件明细补全
            seen = data.get("seen")
            if seen is None:
                seen = {eid: ev.digest for eid, ev in events.items()}
            self._seen = dict(seen)
            self._event_seq = {
                k: int(v) for k, v in data.get("event_seq", {}).items()}
            self._alert_seq = {
                k: int(v) for k, v in data.get("alert_seq", {}).items()}
