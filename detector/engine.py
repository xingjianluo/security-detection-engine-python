"""引擎门面：归一化 -> 规则判定 -> 告警生命周期 -> 流水。

一致性保证
==========
- 全局 ``threading.RLock`` 串行化摄入/规则发布/状态变更/查询；
- 批次级违规（超条数/超字节/背压拒绝）整批拒绝，无任何写入；
- 单条事件违规只拒绝该条，其余条目原子提交，失败不污染已有状态；
- 事件幂等：相同 event_id 的重试/并发投递仅第一次生效，后续返回
  dedup_hit，不产生重复事件、重复告警或重复计数；
- 规则发布保留全部历史 revision，告警绑定命中时刻的 revision，
  更新规则不改写历史结论；
- 每个事件的判定结论写入流水（含输入摘要、命中规则版本与判定依据），
  重放按流水顺序重建并可逐条核对。
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable

from . import alerts as alerts_mod
from . import normalize, persistence, rules as rules_mod
from .config import Config
from .errors import (
    BackpressureError,
    BatchOverSizeError,
    BatchTooLargeError,
    SnapshotError,
    StaleEventError,
)
from .models import (
    Alert,
    AlertState,
    BatchResult,
    Event,
    EventOutcome,
    EventResult,
    JournalEntry,
    Rule,
    Severity,
    input_digest,
    rule_from_dict,
    rule_to_dict,
    utcnow,
)
from .store import Store

log = logging.getLogger("detector.engine")


class Engine:
    def __init__(self, config: Config | None = None, *, persist: bool = False) -> None:
        self.config = config or Config()
        self.store = Store()
        self._lock = threading.RLock()
        self._persist = persist
        # 待处理积压（摄入后尚未完成判定的计数），用于背压
        self._inflight = 0
        self._inflight_cond = threading.Condition(self._lock)
        # 淘汰/归档串行化：与引擎锁分离，归档写盘不阻塞摄入判定
        self._retention_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # 规则
    # ------------------------------------------------------------------ #
    def publish_rules_document(self, raw: dict, *, revision: int | None = None) -> int:
        """校验并发布一份规则文档，返回新 revision。"""
        rules, doc_rev = rules_mod.load_rule_document(raw)
        rev = revision if revision is not None else doc_rev
        if rev <= 0:
            rev = self.store.current_revision() + 1
        with self._lock:
            # revision 必须单调推进
            if rev <= self.store.current_revision():
                from .errors import RuleValidationError

                raise RuleValidationError(
                    f"rule revision {rev} is not greater than current "
                    f"{self.store.current_revision()}"
                )
            self.store.publish_rules(rev, rules)
            self._write_journal(
                "rules_published",
                {"revision": rev, "rule_ids": [r.rule_id for r in rules],
                 # 规则原文随流水保存：重启恢复与重放自包含，
                 # 不依赖 rules_dir 当前内容
                 "rules": [rule_to_dict(r) for r in rules],
                 "document_digest": input_digest(raw)},
            )
        log.info("rules published revision=%s rules=%s", rev, [r.rule_id for r in rules])
        return rev

    # 向后友好的别名
    def publish_rules_file(self, raw: dict) -> int:
        return self.publish_rules_document(raw)

    def load_rules_from_dir(self, path: Path | str | None = None) -> int:
        directory = Path(path) if path is not None else self.config.rules_dir
        rules, rev = rules_mod.load_rules_dir(directory)
        if rev <= 0:
            rev = self.store.current_revision() + 1
        with self._lock:
            if rev <= self.store.current_revision():
                rev = self.store.current_revision() + 1
            rules = [_restamp(r, rev) for r in rules]
            # 幂等：目录内容与当前生效版本一致时不产生新 revision
            # （重启自动加载不会无谓推进规则版本）
            current = self.store.active_rules()
            if current and _rules_content_key(current) == _rules_content_key(rules):
                log.info("rules unchanged, keep revision=%s",
                         self.store.current_revision())
                return self.store.current_revision()
            self.store.publish_rules(rev, rules)
            # 组合文档（固定规则 id 顺序）作为重放可核对的原文摘要
            combined = {
                "format_version": max(r.version for r in rules),
                "revision": rev,
                "rule_ids": sorted(r.rule_id for r in rules),
                "source_dir": str(directory),
            }
            self._write_journal(
                "rules_published",
                {"revision": rev, "rule_ids": [r.rule_id for r in rules],
                 "source": str(directory),
                 "rules": [rule_to_dict(r) for r in rules],
                 "document_digest": input_digest(combined)},
            )
        return rev

    # ------------------------------------------------------------------ #
    # 摄入
    # ------------------------------------------------------------------ #
    def ingest_batch(self, payloads: list[dict], *, source: str) -> BatchResult:
        """事务性摄入整批。"""
        if not isinstance(payloads, list):
            from .errors import EventValidationError

            raise EventValidationError("batch must be a list", reason="malformed_batch")

        # 1) 批次级硬限制：违规整批拒绝
        if len(payloads) > self.config.max_batch_size:
            raise BatchTooLargeError(
                f"batch size {len(payloads)} exceeds max {self.config.max_batch_size}"
            )
        batch_bytes = len(
            json.dumps(payloads, ensure_ascii=False, default=str).encode("utf-8")
        )
        if batch_bytes > self.config.max_batch_bytes:
            raise BatchOverSizeError(
                f"batch bytes {batch_bytes} exceeds max {self.config.max_batch_bytes}"
            )
        for i, payload in enumerate(payloads):
            if isinstance(payload, dict):
                size = len(json.dumps(payload, ensure_ascii=False,
                                      default=str).encode("utf-8"))
                if size > self.config.max_event_bytes:
                    raise BatchOverSizeError(
                        f"event #{i} bytes {size} exceeds max "
                        f"{self.config.max_event_bytes}",
                        reason="event_oversize_bytes",
                    )

        # 2) 归一化（纯函数，不碰状态）
        events, rejected = normalize.normalize_batch(payloads, source=source)

        # 3) 背压：获取积压许可
        self._acquire_capacity(len(events))
        try:
            result = BatchResult()
            for placeholder, reason, detail in rejected:
                result.rejected.append(EventResult(
                    event_id=placeholder, outcome=EventOutcome.REJECTED,
                    reason=reason, detail=detail))
            # 4) 锁内逐条原子处理（时间窗校验 -> 幂等 -> 判定）
            for event in events:
                result.accepted.append(self._process_event(event))
            # 5) 保留策略（evict）：超限淘汰最旧历史并归档
            result.evicted.extend(self._enforce_retention())
            # 批次是否整体被拒（仅批次级异常路径会置位，此处保持 False）
            return result
        finally:
            with self._inflight_cond:
                self._inflight = max(0, self._inflight - len(events))
                self._inflight_cond.notify_all()

    def _acquire_capacity(self, count: int) -> None:
        with self._inflight_cond:
            if self._inflight + count > self.config.max_inflight_events:
                if self.config.on_backpressure == "reject":
                    raise BackpressureError(
                        f"inflight {self._inflight} + {count} > "
                        f"{self.config.max_inflight_events}; rejected by policy"
                    )
                # delay：等待积压回落（带超时防止无界等待）
                while self._inflight + count > self.config.max_inflight_events:
                    if not self._inflight_cond.wait(timeout=30.0):
                        raise BackpressureError(
                            "backpressure wait timed out",
                            reason="backpressure_timeout",
                        )
            self._inflight += count

    def _check_time_window(self, event: Event) -> None:
        now = utcnow()
        if event.occurred_at < now - timedelta(seconds=self.config.max_out_of_order_s):
            raise StaleEventError(
                f"event {event.event_id} occurred at {event.occurred_at.isoformat()} "
                f"older than {self.config.max_out_of_order_s}s",
                reason="stale_event",
            )
        if event.occurred_at > now + timedelta(seconds=self.config.future_tolerance_s):
            from .errors import InvalidTimestampError

            raise InvalidTimestampError(
                f"event {event.event_id} occurs too far in the future: "
                f"{event.occurred_at.isoformat()}",
                reason="future_timestamp",
            )

    def _process_event(self, event: Event) -> EventResult:
        """在引擎锁内处理单条归一事件，幂等且产生确定告警结论。"""
        with self._lock:
            # 时间窗
            try:
                self._check_time_window(event)
            except Exception as exc:  # noqa: BLE001
                reason = getattr(exc, "reason", "event_validation_failed")
                return EventResult(event_id=event.event_id,
                                   outcome=EventOutcome.REJECTED,
                                   digest=event.digest, reason=reason,
                                   detail=str(exc))

            # 幂等：并发/重试只有第一次写入生效
            # （含已淘汰但保留锚点的历史事件：重启/淘汰后重复投递仍判已处理）
            if self.store.seen_event(event.event_id):
                log.info("dedup event_id=%s digest=%s", event.event_id, event.digest)
                return EventResult(event_id=event.event_id,
                                   outcome=EventOutcome.ACCEPTED,
                                   digest=event.digest, dedup_hit=True)

            # 保留上限（reject 策略）：历史触顶时拒绝新进入，原因码可区分
            if (self.config.on_retention_exceeded == "reject"
                    and self._retention_full()):
                log.info("retention reject event_id=%s digest=%s",
                         event.event_id, event.digest)
                return EventResult(
                    event_id=event.event_id,
                    outcome=EventOutcome.REJECTED,
                    digest=event.digest,
                    reason="retention_limit_rejected",
                    detail="retention limit reached; new history rejected "
                           "by policy 'reject'")

            self.store.put_event_if_absent(event)

            self._write_journal("event_accepted", {
                "event_id": event.event_id, "source": event.source,
                "digest": event.digest,
                # 完整归一事件随流水保存，保证重放自包含、可复现
                "event": event.to_dict(),
            })

            # 规则判定（命中时版本）
            rules = self.store.active_rules()
            rule, trace = rules_mod.match_any(rules, event)
            log.info(
                "judge event_id=%s digest=%s matched=%s rule=%s version=%s revision=%s",
                event.event_id, event.digest, trace.matched, trace.rule_id,
                trace.rule_version, trace.rule_revision,
            )
            if rule is None:
                self._write_journal("event_no_match", {
                    "event_id": event.event_id, "digest": event.digest,
                    "rule_revision": self.store.current_revision(),
                })
                return EventResult(event_id=event.event_id,
                                   outcome=EventOutcome.ACCEPTED,
                                   digest=event.digest)

            self._apply_match(rule, event, trace)
            return EventResult(event_id=event.event_id,
                               outcome=EventOutcome.ACCEPTED,
                               digest=event.digest)

    def _apply_match(self, rule: Rule, event: Event, trace) -> None:
        """去重/合并/抑制编排，全部在引擎锁内。"""
        corr = alerts_mod.correlation_key_of(rule, event)
        merge = alerts_mod.merge_key_of(rule, event)
        existing = self.store.open_alert_by_keys(merge, corr)

        if existing is not None and not existing.state.is_terminal:
            if alerts_mod.should_dedup(existing, event, rule):
                counted = alerts_mod.fold_event(existing, event, trace)
                self.store.update_alert(existing)
                self._write_journal("alert_dedup", {
                    "alert_id": existing.alert_id, "event_id": event.event_id,
                    "digest": event.digest, "counted": counted,
                    "rule_revision": rule.revision,
                })
                return

        # 新告警候选：先判定抑制（针对其它 merge/corr 键的活动抑制者）
        candidate = alerts_mod.make_alert(rule, event, trace)
        for suppressor in self.store.active_suppressors(event.occurred_at):
            if suppressor.alert_id == candidate.alert_id:
                continue
            if alerts_mod.suppression_blocks(suppressor, candidate.severity,
                                             event.occurred_at):
                candidate.state = AlertState.SUPPRESSED
                candidate.suppressed_by = suppressor.alert_id
                self.store.put_alert(candidate)
                self._write_journal("alert_suppressed", {
                    "alert_id": candidate.alert_id,
                    "suppressed_by": suppressor.alert_id,
                    "event_id": event.event_id, "digest": event.digest,
                    "rule_id": rule.rule_id, "rule_version": rule.version,
                    "rule_revision": rule.revision, "checks": trace.checks,
                })
                return

        self.store.put_alert(candidate)
        self._write_journal("alert_opened", {
            "alert_id": candidate.alert_id, "event_id": event.event_id,
            "digest": event.digest, "rule_id": rule.rule_id,
            "rule_version": rule.version, "rule_revision": rule.revision,
            "checks": trace.checks,
        })

    def _replay_event(self, event: Event) -> dict[str, Any]:
        """重放路径：重建事件存储并重新判定，不做时间窗/幂等拦截。

        返回结论字典（kind ∈ no_match/dedup/opened/suppressed 及规则绑定）。
        调用方负责持锁（本方法内部加锁）。
        """
        with self._lock:
            self.store.put_event_if_absent(event)
            rules = self.store.active_rules()
            rule, trace = rules_mod.match_any(rules, event)
            if rule is None:
                return {"kind": "event_no_match"}

            corr = alerts_mod.correlation_key_of(rule, event)
            merge = alerts_mod.merge_key_of(rule, event)
            existing = self.store.open_alert_by_keys(merge, corr)
            if existing is not None and alerts_mod.should_dedup(existing, event, rule):
                alerts_mod.fold_event(existing, event, trace)
                self.store.update_alert(existing)
                return {"kind": "alert_dedup", "alert_id": existing.alert_id,
                        "rule_id": rule.rule_id, "rule_version": rule.version,
                        "rule_revision": rule.revision}

            candidate = alerts_mod.make_alert(rule, event, trace)
            for suppressor in self.store.active_suppressors(event.occurred_at):
                if suppressor.alert_id == candidate.alert_id:
                    continue
                if alerts_mod.suppression_blocks(suppressor, candidate.severity,
                                                 event.occurred_at):
                    candidate.state = AlertState.SUPPRESSED
                    candidate.suppressed_by = suppressor.alert_id
                    self.store.put_alert(candidate)
                    return {"kind": "alert_suppressed",
                            "alert_id": candidate.alert_id,
                            "suppressed_by": suppressor.alert_id,
                            "rule_id": rule.rule_id, "rule_version": rule.version,
                            "rule_revision": rule.revision}
            self.store.put_alert(candidate)
            return {"kind": "alert_opened", "alert_id": candidate.alert_id,
                    "rule_id": rule.rule_id, "rule_version": rule.version,
                    "rule_revision": rule.revision}

    def merge_alert(self, child_alert_id: str, parent_alert_id: str) -> Alert:
        """显式合并：child -> MERGED（终态），归属 parent。"""
        with self._lock:
            child = self.store.get_alert(child_alert_id)
            parent = self.store.get_alert(parent_alert_id)
            if child is None or parent is None:
                from .errors import AlertNotFoundError

                raise AlertNotFoundError(
                    f"child={child_alert_id!r} parent={parent_alert_id!r}"
                )
            alerts_mod.transition(child, AlertState.MERGED)
            child.merged_into = parent_alert_id
            self.store.update_alert(child)
            self._write_journal("alert_merged", {
                "alert_id": child_alert_id, "merged_into": parent_alert_id})
            return child

    # ------------------------------------------------------------------ #
    # 告警状态变更
    # ------------------------------------------------------------------ #
    def acknowledge(self, alert_id: str) -> Alert:
        with self._lock:
            alert = self._require_alert(alert_id)
            alerts_mod.transition(alert, AlertState.ACKNOWLEDGED)
            self.store.update_alert(alert)
            self._write_journal("alert_acknowledged", {"alert_id": alert_id})
            return alert

    def resolve(self, alert_id: str) -> Alert:
        with self._lock:
            alert = self._require_alert(alert_id)
            alerts_mod.transition(alert, AlertState.RESOLVED)
            self.store.update_alert(alert)
            self._write_journal("alert_resolved", {"alert_id": alert_id})
            return alert

    def reopen(self, alert_id: str) -> Alert:
        with self._lock:
            alert = self._require_alert(alert_id)
            alerts_mod.transition(alert, AlertState.OPEN)
            alert.suppressed_by = None
            self.store.update_alert(alert)
            self._write_journal("alert_reopened", {"alert_id": alert_id})
            return alert

    def suppress_expired_tick(self, at=None) -> list[Alert]:
        """把抑制窗口已过的 SUPPRESSED 告警恢复 OPEN。"""
        at = at or utcnow()
        changed: list[Alert] = []
        with self._lock:
            for alert in self.store.all_alerts():
                if alert.state != AlertState.SUPPRESSED:
                    continue
                suppressor = (
                    self.store.get_alert(alert.suppressed_by)
                    if alert.suppressed_by else None
                )
                still = (
                    suppressor is not None
                    and alerts_mod.suppression_blocks(
                        suppressor, alert.severity, at)
                )
                if not still:
                    alerts_mod.transition(alert, AlertState.OPEN)
                    alert.suppressed_by = None
                    self.store.update_alert(alert)
                    self._write_journal("alert_reopened",
                                        {"alert_id": alert.alert_id,
                                         "reason": "suppress_window_expired"})
                    changed.append(alert)
        return changed

    def _require_alert(self, alert_id: str) -> Alert:
        from .errors import AlertNotFoundError

        alert = self.store.get_alert(alert_id)
        if alert is None:
            raise AlertNotFoundError(f"alert {alert_id!r} not found")
        return alert

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def get_alert(self, alert_id: str) -> Alert | None:
        with self._lock:
            return self.store.get_alert(alert_id)

    def list_alerts(self) -> list[Alert]:
        with self._lock:
            return self.store.all_alerts()

    def get_event(self, event_id: str) -> Event | None:
        with self._lock:
            return self.store.get_event(event_id)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            alerts_ = self.store.all_alerts()
            by_state: dict[str, int] = {}
            for a in alerts_:
                by_state[a.state.value] = by_state.get(a.state.value, 0) + 1
            return {
                "events": self.store.event_count(),
                "alerts": len(alerts_),
                "alerts_by_state": by_state,
                "rule_revision": self.store.current_revision(),
                "inflight": self._inflight,
                "journal": self.store.journal_len(),
                "event_tombstones": self.store.tombstone_count(),
                "retention": {
                    "policy": self.config.on_retention_exceeded,
                    "max_events": self.config.max_retained_events,
                    "max_alerts": self.config.max_retained_alerts,
                    "max_journal": self.config.max_retained_journal,
                    "archive_enabled": self.config.archive_enabled,
                },
            }

    # ------------------------------------------------------------------ #
    # 持久化
    # ------------------------------------------------------------------ #
    def _write_journal(self, kind: str, payload: dict) -> JournalEntry:
        entry = JournalEntry(
            seq=self.store.next_seq(),
            ts=utcnow(),
            kind=kind,
            payload=payload,
            digest=input_digest({"kind": kind, "payload": payload}),
        )
        self.store.append_journal(entry)
        if self._persist:
            persistence.append_journal_file(self.config.journal_path, [entry])
            every = self.config.snapshot_every
            if every > 0 and entry.seq % every == 0:
                # 周期性自动快照：重启恢复只需回放快照之后的流水尾
                persistence.export_snapshot(self.store, self.config.snapshot_path)
        return entry

    # ------------------------------------------------------------------ #
    # 重启接续（恢复）
    # ------------------------------------------------------------------ #
    def recover(self) -> dict[str, Any]:
        """从本地快照 + 流水尾恢复运行状态（persist 模式启动时自动调用）。

        - 快照覆盖 seq 之前的全部状态（事件/告警/规则历史/幂等锚点）；
        - 流水文件中 seq 大于快照 seq 的条目按序重放，重建最新状态；
        - 恢复后重复投递已处理事件仍判 dedup，告警状态与规则版本延续。
        """
        restored: dict[str, Any] = {"snapshot": False, "journal_entries": 0}
        if not self._persist:
            return restored
        with self._lock:
            snap = persistence.load_snapshot(self.config.snapshot_path)
            if snap is not None:
                self.store.restore(snap)
                restored["snapshot"] = True
            snap_seq = self.store._seq  # noqa: SLF001
            rows = persistence.read_journal(self.config.journal_path)
            for row in rows:
                if int(row["seq"]) <= snap_seq:
                    continue
                entry = persistence.entry_from_dict(row)
                self._apply_journal_entry(entry)
                self.store.append_journal(entry)
                self.store.advance_seq(entry.seq)
                restored["journal_entries"] += 1
        log.info("recover: snapshot=%s journal_tail=%s",
                 restored["snapshot"], restored["journal_entries"])
        return restored

    def _apply_journal_entry(self, entry: JournalEntry) -> None:
        """把一条流水重新作用到存储（恢复专用，调用方持锁）。"""
        kind, payload = entry.kind, entry.payload
        if kind == "rules_published":
            rev = int(payload["revision"])
            rules = [rule_from_dict(r) for r in payload.get("rules", [])]
            if not rules:
                # 兼容旧版流水（无规则原文）：按摘要从 rules_dir 解析
                rules = _rules_bundle_for_digest(
                    self.config.rules_dir, payload.get("document_digest"))
            self.store.publish_rules(rev, [_restamp(r, rev) for r in rules])
            return
        if kind == "event_accepted":
            self._replay_event(_event_from_journal(payload))
            return
        if kind in ("alert_acknowledged", "alert_resolved",
                    "alert_reopened", "alert_merged"):
            self._apply_alert_transition(kind, payload)
            return
        # alert_opened / alert_suppressed / alert_dedup / event_no_match
        # 由 event_accepted 的重放间接重建，无需单独作用

    def _apply_alert_transition(self, kind: str, payload: dict) -> None:
        alert = self.store.get_alert(payload.get("alert_id", ""))
        if alert is None:
            log.warning("recover: alert %s missing for %s, skipped",
                        payload.get("alert_id"), kind)
            return
        try:
            if kind == "alert_acknowledged":
                alerts_mod.transition(alert, AlertState.ACKNOWLEDGED)
            elif kind == "alert_resolved":
                alerts_mod.transition(alert, AlertState.RESOLVED)
            elif kind == "alert_reopened":
                alerts_mod.transition(alert, AlertState.OPEN)
                alert.suppressed_by = None
            elif kind == "alert_merged":
                alerts_mod.transition(alert, AlertState.MERGED)
                alert.merged_into = payload.get("merged_into")
        except Exception:  # noqa: BLE001 - 恢复不因单条状态流水中断
            log.exception("recover: transition %s failed for alert %s",
                          kind, alert.alert_id)
            return
        self.store.update_alert(alert)

    # ------------------------------------------------------------------ #
    # 有界保留与归档
    # ------------------------------------------------------------------ #
    @property
    def _archive_path(self) -> Path:
        return Path(self.config.archive_dir) / "archive.jsonl"

    def _retention_full(self) -> bool:
        """任一已配置保留上限触顶（reject 策略的准入判定）。"""
        cfg = self.config
        if cfg.max_retained_events and \
                self.store.event_count() >= cfg.max_retained_events:
            return True
        if cfg.max_retained_alerts and \
                self.store.alert_count() >= cfg.max_retained_alerts:
            return True
        return bool(cfg.max_retained_journal
                    and self.store.journal_len() >= cfg.max_retained_journal)

    def _plan_eviction(self) -> dict[str, list]:
        """锁内确定淘汰候选（不变更状态）。只淘汰历史明细：
        事件明细（留幂等锚点）、终态告警、最旧流水；活动告警、
        去重/抑制锚点绝不淘汰。"""
        cfg = self.config
        plan: dict[str, list] = {"events": [], "alerts": [], "journal": []}
        if cfg.max_retained_events:
            over = self.store.event_count() - cfg.max_retained_events
            if over > 0:
                plan["events"] = self.store.peek_oldest_events(over)
        if cfg.max_retained_alerts:
            over = self.store.alert_count() - cfg.max_retained_alerts
            if over > 0:
                plan["alerts"] = self.store.peek_terminal_alerts(over)
        if cfg.max_retained_journal:
            over = self.store.journal_len() - cfg.max_retained_journal
            if over > 0:
                plan["journal"] = self.store.journal()[:over]
        return plan

    def _enforce_retention(self) -> list[dict]:
        """evict 策略：超限就把最旧历史归档后从热存储淘汰。

        顺序保证：先写归档（失败则显式报错、状态原封不动），
        再变更内存，最后落快照/截断流水文件。归档写盘在引擎锁外
        进行，不阻塞正常摄入。
        """
        if self.config.on_retention_exceeded != "evict":
            return []
        if not self._retention_lock.acquire(blocking=False):
            # 另一次淘汰进行中：本轮跳过，下一轮再收敛
            return []
        try:
            with self._lock:
                plan = self._plan_eviction()
            if not any(plan.values()):
                return []

            # 1) 归档（锁外写盘）：失败抛 ArchiveError，内存/流水均未变更
            if self.config.archive_enabled:
                records = (
                    [persistence.archive_record("event", e.to_dict())
                     for e in plan["events"]]
                    + [persistence.archive_record("alert", a.to_dict())
                       for a in plan["alerts"]]
                    + [persistence.archive_record(
                        "journal", persistence.entry_to_dict(entry))
                       for entry in plan["journal"]]
                )
                persistence.append_archive(self._archive_path, records)

            # 2) 变更内存状态（淘汰），3) 持久化收尾
            with self._lock:
                evicted_events = self.store.evict_oldest_events(
                    len(plan["events"]))
                evicted_alerts = self.store.evict_terminal_alerts(
                    len(plan["alerts"]))
                evicted_journal = self.store.trim_journal(len(plan["journal"]))
                if self._persist:
                    # 快照反映淘汰后状态：恢复时无需依赖已淘汰的流水段
                    persistence.export_snapshot(
                        self.store, self.config.snapshot_path)
                    if evicted_journal:
                        persistence.rewrite_journal_file(
                            self.config.journal_path, self.store.journal())

            info: list[dict] = []
            for e in evicted_events:
                info.append({"kind": "event", "event_id": e.event_id,
                             "digest": e.digest, "reason": "retention_evicted"})
            for a in evicted_alerts:
                info.append({"kind": "alert", "alert_id": a.alert_id,
                             "state": a.state.value,
                             "reason": "retention_evicted"})
            for entry in evicted_journal:
                info.append({"kind": "journal", "seq": entry.seq,
                             "entry_kind": entry.kind,
                             "reason": "retention_evicted"})
            if info:
                log.info("retention evicted: events=%d alerts=%d journal=%d "
                         "archived_to=%s", len(evicted_events),
                         len(evicted_alerts), len(evicted_journal),
                         self._archive_path)
            return info
        finally:
            self._retention_lock.release()

    def journal(self) -> list[JournalEntry]:
        with self._lock:
            return self.store.journal()

    def snapshot(self) -> dict:
        with self._lock:
            return self.store.snapshot()

    def save_snapshot(self, path: Path | None = None) -> Path:
        target = Path(path) if path else self.config.snapshot_path
        with self._lock:
            persistence.export_snapshot(self.store, target)
        return target

    def restore_snapshot(self, path: Path | None = None) -> bool:
        target = Path(path) if path else self.config.snapshot_path
        data = persistence.load_snapshot(target)
        if data is None:
            return False
        with self._lock:
            self.store.restore(data)
        return True


def _restamp(rule: Rule, revision: int) -> Rule:
    return Rule(**{**rule.__dict__, "revision": revision})


def _rules_content_key(rules: list[Rule]) -> list[tuple]:
    """规则集内容指纹（忽略 revision 戳），用于幂等发布判定。"""
    key = []
    for r in sorted(rules, key=lambda x: x.rule_id):
        d = rule_to_dict(r)
        d.pop("revision", None)
        key.append(tuple(sorted(d.items(), key=lambda kv: kv[0])))
    return key


def _rule_bundles_from_dir(rules_dir: Path) -> dict[str, list[Rule]]:
    """规则来源摘要 -> 规则原文集合（支持单文档与目录聚合两种发布方式）。"""
    bundles: dict[str, list[Rule]] = {}
    rules_dir = Path(rules_dir)
    if not rules_dir.exists():
        return bundles
    for file in sorted(rules_dir.glob("*.json")):
        raw = json.loads(file.read_text(encoding="utf-8"))
        doc_rules, _rev = rules_mod.load_rule_document(raw)
        bundles[input_digest(raw)] = doc_rules
    try:
        dir_rules, dir_rev = rules_mod.load_rules_dir(rules_dir)
        combined = {
            "format_version": max(r.version for r in dir_rules),
            "revision": dir_rev,
            "rule_ids": sorted(r.rule_id for r in dir_rules),
            "source_dir": str(rules_dir),
        }
        bundles[input_digest(combined)] = dir_rules
    except Exception:  # noqa: BLE001 - 目录聚合不可用时仍可用单文档匹配
        pass
    return bundles


def _rules_bundle_for_digest(rules_dir: Path, digest: str | None) -> list[Rule]:
    """按文档摘要从 rules_dir 解析规则原文；缺失显式报错。"""
    bundle = _rule_bundles_from_dir(rules_dir).get(digest) if digest else None
    if bundle is None:
        raise SnapshotError(
            f"rule bundle digest {digest!r} not found in {rules_dir}; "
            f"cannot restore historical rules"
        )
    return bundle


def build_engine(
    config: Config | None = None,
    *,
    autoload: bool = True,
    persist: bool | None = None,
) -> Engine:
    """构造引擎；autoload 时从 rules_dir 加载初始规则（目录可不存在）。

    persist 缺省取 ``config.persist``（默认开启）：启动时自动从
    本地快照 + 流水恢复重启前状态，无需额外开关或特殊调用。
    """
    cfg = config or Config()
    use_persist = cfg.persist if persist is None else persist
    engine = Engine(cfg, persist=use_persist)
    if use_persist:
        engine.recover()
    if autoload and engine.config.rules_dir.exists():
        engine.load_rules_from_dir()
    return engine


# ---------------------------------------------------------------------- #
# 重放
# ---------------------------------------------------------------------- #

# 重放时对每种流水结论需要核对的字段
_OUTCOME_KINDS = frozenset({
    "alert_opened", "alert_suppressed", "alert_dedup", "event_no_match",
})


def _event_from_journal(payload: dict) -> Event:
    raw = payload["event"]
    from .models import parse_ts

    return Event(
        event_id=raw["event_id"],
        source=raw["source"],
        event_type=raw["event_type"],
        severity=Severity(raw["severity"]),
        occurred_at=parse_ts(raw["occurred_at"]),
        ingested_at=parse_ts(raw["ingested_at"]),
        src_ip=raw.get("src_ip"),
        dst_ip=raw.get("dst_ip"),
        user=raw.get("user"),
        host=raw.get("host"),
        action=raw.get("action"),
        raw=raw.get("raw", {}),
        digest=raw.get("digest", ""),
    )


def replay(
    journal_path: Path | str,
    config: Config | None = None,
    *,
    include_archive: bool = False,
    archive_path: Path | str | None = None,
) -> tuple[Engine, list[dict]]:
    """基于流水重建引擎并逐条核对重放结论。

    流水自包含：``rules_published`` 带规则原文，``event_accepted``
    带完整归一事件。重放按 seq 顺序重新执行规则判定与告警编排，
    并把每个事件的结论（无命中/去重/开告警/抑制、命中的规则版本）
    与原始流水逐条比对；任何不一致抛 :class:`ReplayConsistencyError`。

    ``include_archive=True`` 时把本地归档中被淘汰的流水段显式纳入
    处理顺序（按 seq 归并去重），用于完整重放或用归档重建状态；
    日常重放不加载归档。归档损坏会显式抛 :class:`ArchiveError`。

    返回 ``(重建后的引擎, 逐条重放报告)``。
    """
    from .errors import ReplayConsistencyError, RuleValidationError

    cfg = config or Config()
    rows = persistence.read_journal(Path(journal_path))
    if include_archive:
        apath = (Path(archive_path) if archive_path
                 else Path(cfg.archive_dir) / "archive.jsonl")
        seen = {int(r["seq"]) for r in rows}
        for record in persistence.read_archive(apath):
            if record.get("record_kind") != "journal":
                continue
            data = record["data"]
            if int(data["seq"]) not in seen:
                rows.append(data)
                seen.add(int(data["seq"]))
        rows.sort(key=lambda r: int(r["seq"]))
    engine = Engine(cfg, persist=False)

    # 规则来源摘要 -> 规则原文集合（旧版流水无内嵌原文时的回退来源）
    digest_to_bundle = _rule_bundles_from_dir(cfg.rules_dir)

    # event_id -> 原始结论流水（用于核对）
    def _next_outcome(seq_after: int, event_id: str) -> dict | None:
        for row in rows:
            if row["seq"] <= seq_after:
                continue
            p = row.get("payload", {})
            if p.get("event_id") == event_id and row["kind"] in _OUTCOME_KINDS:
                return row
        return None

    report: list[dict] = []
    for row in rows:
        kind, payload, seq = row["kind"], row["payload"], row["seq"]
        item: dict[str, Any] = {"seq": seq, "kind": kind, "consistent": True}

        if kind == "rules_published":
            # 优先使用流水内嵌的规则原文（自包含）；旧版流水回退到
            # 按 document_digest 从 rules_dir 解析
            if payload.get("rules"):
                bundle = [rule_from_dict(r) for r in payload["rules"]]
            else:
                digest = payload.get("document_digest")
                bundle = digest_to_bundle.get(digest) if digest else None
            if bundle is None:
                raise ReplayConsistencyError(
                    f"seq={seq}: rule bundle digest "
                    f"{payload.get('document_digest')!r} not found in "
                    f"{cfg.rules_dir}; cannot reproduce revision "
                    f"{payload.get('revision')}"
                )
            rev = int(payload["revision"])
            engine.store.publish_rules(rev, [_restamp(r, rev) for r in bundle])
            item["revision"] = rev
            report.append(item)
            continue

        if kind == "event_accepted":
            event = _event_from_journal(payload)
            # 摘要核对：重放输入的归一摘要必须与流水记录一致，防止篡改/漂移
            if event.digest != payload.get("digest"):
                raise ReplayConsistencyError(
                    f"seq={seq}: event {event.event_id} digest "
                    f"{event.digest!r} != journal {payload.get('digest')!r}"
                )
            outcome_row = _next_outcome(seq, event.event_id)
            # 在已恢复的规则历史下重新判定（bypass 时间窗与幂等：重放历史数据）
            replayed = engine._replay_event(event)
            item["event_id"] = event.event_id
            item["input_digest"] = event.digest
            item["replayed"] = replayed
            if outcome_row is None:
                raise ReplayConsistencyError(
                    f"seq={seq}: no original outcome for event {event.event_id}"
                )
            orig_kind = outcome_row["kind"]
            item["original_kind"] = orig_kind
            op = outcome_row["payload"]
            if replayed["kind"] != orig_kind:
                raise ReplayConsistencyError(
                    f"event {event.event_id}: original={orig_kind} "
                    f"replay={replayed['kind']}"
                )
            if orig_kind in ("alert_opened", "alert_suppressed"):
                same = (
                    op.get("rule_id") == replayed.get("rule_id")
                    and op.get("rule_version") == replayed.get("rule_version")
                    and op.get("rule_revision") == replayed.get("rule_revision")
                )
                if orig_kind == "alert_suppressed":
                    same = (
                        same
                        and op.get("suppressed_by") == replayed.get("suppressed_by")
                    )
                item["rule_id"] = replayed.get("rule_id")
                item["rule_version"] = replayed.get("rule_version")
                item["rule_revision"] = replayed.get("rule_revision")
                if not same:
                    raise ReplayConsistencyError(
                        f"event {event.event_id}: rule binding differs "
                        f"original={op} replay={replayed}"
                    )
            report.append(item)
            continue

        # 状态类/去重类流水已在事件重放中间接重建，这里仅登记
        report.append(item)

    # 重放后引擎状态与流水结尾应自洽：流水条目数核对
    expected_events = sum(1 for r in rows if r["kind"] == "event_accepted")
    if engine.store.event_count() != expected_events:
        raise ReplayConsistencyError(
            f"event count after replay {engine.store.event_count()} != "
            f"journal event_accepted {expected_events}"
        )
    return engine, report


def replay_from_snapshot(
    snapshot_path: Path | str,
    journal_path: Path | str,
    config: Config | None = None,
) -> tuple[Engine, list[dict]]:
    """先恢复快照，再只重放快照之后的流水行（snapshot_after_seq 之后）。"""
    cfg = config or Config()
    engine = Engine(cfg, persist=False)
    if not engine.restore_snapshot(Path(snapshot_path)):
        raise SnapshotError(f"snapshot not found: {snapshot_path}")
    rows = persistence.read_journal(Path(journal_path))
    after = engine.store.journal_len()  # 快照不保存流水本身，故通常为 0
    # 快照存储 seq；流水条目按 seq > 快照seq 过滤
    snap_seq = engine.store._seq  # noqa: SLF001
    tail = [r for r in rows if r["seq"] > snap_seq]

    # 规则历史已随快照恢复，直接重放事件流
    report: list[dict] = []
    for row in tail:
        if row["kind"] != "event_accepted":
            continue
        event = _event_from_journal(row["payload"])
        replayed = engine._replay_event(event)
        report.append({
            "seq": row["seq"], "event_id": event.event_id,
            "input_digest": event.digest, "replayed": replayed,
            "consistent": True,
        })
    return engine, report
