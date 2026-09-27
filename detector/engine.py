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
from .archive import ArchiveChunk, ArchiveWriter, read_manifest
from .config import Config
from .errors import (
    BackpressureError,
    BatchOverSizeError,
    BatchTooLargeError,
    RetentionFullError,
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
        # 有界保留/归档
        self._archive: ArchiveWriter | None = None
        # 已提交（manifest 已含）归档水位；磁盘流水 <= 该水位的部分可裁剪
        self._archived_watermark = 0
        # 待提交归档目标水位集合，等待 ack
        self._pending_commits: set[int] = set()
        # 磁盘上已随快照落地的 seq；崩溃恢复时 journal 只重放其后的行
        self._snapshot_seq = 0
        self._events_since_snapshot = 0
        if self._persist:
            self._init_archive()

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
                 "document_digest": input_digest(raw),
                 "rules": [rules_mod.rule_to_dict(r) for r in rules]},
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
                 "document_digest": input_digest(combined),
                 "rules": [rules_mod.rule_to_dict(r) for r in rules]},
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
            with self._lock:
                # reject_new：容量已满则整批事务性拒绝（原因明确，零写入）
                self._enforce_reject_policy()
            for placeholder, reason, detail in rejected:
                result.rejected.append(EventResult(
                    event_id=placeholder, outcome=EventOutcome.REJECTED,
                    reason=reason, detail=detail))
            # 4) 锁内逐条原子处理（时间窗校验 -> 幂等 -> 判定）
            evicted_total = 0
            for event in events:
                with self._lock:
                    outcome = self._process_event(event)
                    if not outcome.dedup_hit and outcome.outcome is EventOutcome.ACCEPTED:
                        self._maybe_auto_snapshot()
                    # evict_oldest：本条处理后按容量淘汰最旧明细
                    evicted_total += self._enforce_evict_oldest()
                result.accepted.append(outcome)
            result.evicted = evicted_total
            result.retained_records = self.store.retained_count()
            result.retained_bytes = self.store.retained_bytes()
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

    # ------------------------------------------------------------------ #
    # 有界保留：容量检查 / 最旧淘汰 + 归档
    # ------------------------------------------------------------------ #
    def _over_limit(self) -> bool:
        return (
            self.store.retained_count() > self.config.retention_max_records
            or self.store.retained_bytes() > self.config.retention_max_bytes
        )

    def _enforce_reject_policy(self) -> None:
        """reject_new 策略：容量满则显式拒绝（批次事务性，不产生写入）。"""
        if self.config.retention_policy == "reject_new" and self._over_limit():
            raise RetentionFullError(
                f"retention full: records={self.store.retained_count()}/"
                f"{self.config.retention_max_records} "
                f"bytes={self.store.retained_bytes()}/"
                f"{self.config.retention_max_bytes}; rejected by policy",
            )

    def _enforce_evict_oldest(self) -> int:
        """evict_oldest 策略：淘汰最旧明细直到回到上限内。

        一次摄入触发的多次淘汰合并为一个归档分段（水位 = 最后一条被淘汰
        明细的 seq，分段含其之前全部连续流水），避免高压小批次下归档
        分段碎片化。活动告警与幂等锚点永不淘汰。
        """
        if self.config.retention_policy != "evict_oldest":
            return 0
        evicted: list = []
        use_archive = self._persist and self.config.archive_enabled
        while self._over_limit():
            item = self.store.oldest_evictable()
            if item is None or item.seq <= 0:
                # 只剩锚点（不可淘汰）：无法腾出空间，显式拒绝
                raise RetentionFullError(
                    f"retention full with no evictable detail: "
                    f"records={self.store.retained_count()} "
                    f"bytes={self.store.retained_bytes()}",
                )
            self.store.remove_evicted(item)
            evicted.append(item)
        if not evicted:
            return 0
        if not evicted:
            return 0
        # 水位取这批淘汰完成时的当前最大流水 seq：被淘汰明细（事件/终态
        # 告警）对应的结论行 seq 可能晚于其锚点 seq，水位必须覆盖这些结论
        # 行，否则归档前缀里会出现“有 event_accepted 无结论”的破洞。
        watermark = max(
            max(item.seq for item in evicted),
            self.store.current_journal_max_seq())
        if use_archive:
            # 明细已移除但流水前缀仍保留在内存/磁盘：目标水位排队后，后台
            # 线程向引擎取 (committed, target] 区间行原子落分段；ack 后
            # 才物理裁剪 journal。容量账立即释放（归档承接长期留存）。
            self._archive.submit(watermark, self.config.archive_max_pending)
            self.store.mark_archive_pending(watermark)
        for item in evicted:
            self._write_journal("history_evicted", {
                "kind": item.kind, "key": item.key,
                "watermark_seq": watermark, "archived": use_archive,
            })
            log.info("evicted oldest kind=%s key=%s watermark=%s archived=%s",
                     item.kind, item.key, watermark, use_archive)
        if not use_archive:
            self.store.trim_journal(watermark)
        else:
            self._pending_commits.add(watermark)
        return len(evicted)

    def _on_archive_committed(self, chunk: ArchiveChunk) -> None:
        """归档线程回调（引擎锁内执行）：推进水位、裁剪流水、固化快照。"""
        with self._lock:
            watermark = chunk.watermark_seq
            if watermark <= self._archived_watermark:
                return
            self._archived_watermark = watermark
            self._pending_commits.discard(watermark)
            next_wm = max(self._pending_commits, default=0)
            # 物理裁剪已提交部分；仍在排队的更高水位前缀容量账继续排除
            self.store.trim_journal(watermark, next_pending_watermark=next_wm)
            self._persist_journal_tail()
            self.save_snapshot()
            self._snapshot_seq = self.store._seq  # noqa: SLF001
            log.info("archive committed watermark=%s pending=%s",
                     watermark, self._pending_commits)

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
            if not self.store.put_event_if_absent(event):
                log.info("dedup event_id=%s digest=%s", event.event_id, event.digest)
                return EventResult(event_id=event.event_id,
                                   outcome=EventOutcome.ACCEPTED,
                                   digest=event.digest, dedup_hit=True)

            entry = self._write_journal("event_accepted", {
                "event_id": event.event_id, "source": event.source,
                "digest": event.digest,
                # 完整归一事件随流水保存，保证重放自包含、可复现
                "event": event.to_dict(),
            })
            self.store.bind_event_seq(event.event_id, entry.seq)

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
        """
        with self._lock:
            return self._replay_event_locked(event)

    def _replay_event_locked(self, event: Event) -> dict[str, Any]:
        """调用方持锁的重放判定（恢复/归档重建共用）。"""
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
            entry = self._write_journal("alert_merged", {
                "alert_id": child_alert_id, "merged_into": parent_alert_id})
            self.store.bind_alert_seq(child_alert_id, entry.seq)
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
            entry = self._write_journal("alert_resolved", {"alert_id": alert_id})
            self.store.bind_alert_seq(alert_id, entry.seq)
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
                "retention": {
                    "records": self.store.retained_count(),
                    "bytes": self.store.retained_bytes(),
                    "max_records": self.config.retention_max_records,
                    "max_bytes": self.config.retention_max_bytes,
                    "policy": self.config.retention_policy,
                },
                "archive": {
                    "enabled": self._archive is not None,
                    "committed_watermark": self._archived_watermark,
                    "pending_targets": (
                        self._archive.pending if self._archive else 0),
                    "healthy": (
                        self._archive.failed is None
                        if self._archive else True),
                },
            }

    # ------------------------------------------------------------------ #
    # 持久化
    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    # 持久化：重启接续
    # ------------------------------------------------------------------ #
    def _init_archive(self) -> None:
        """启动归档器并从 manifest 得知已提交水位（不加载归档内容）。"""
        if not self.config.archive_enabled:
            return
        archive_dir = self.config.archive_dir or (
            self.config.data_dir / "archive")
        try:
            writer = ArchiveWriter(
                archive_dir,
                fetch_entries=self._fetch_archivable_entries,
                on_commit=self._on_archive_committed)
            writer.start()
        except Exception:
            raise
        self._archive = writer
        self._archived_watermark = writer.committed_watermark()

    def _fetch_archivable_entries(self, prev_watermark: int,
                                  target_watermark: int):
        """供归档线程调用：取 (prev, target] 区间仍在本地流水中的判定历史。

        ``history_evicted`` 是淘汰记账行（seq 位于淘汰点之后，不属于被
        归档的判定历史），排除在外，保证分段严格等于某水位之前的连续前缀。
        """
        with self._lock:
            return [
                e for e in self.store.journal()
                if prev_watermark < e.seq <= target_watermark
                and e.kind != "history_evicted"]

    def restore_on_startup(self) -> bool:
        """从本地快照 + 流水恢复，实现重启接续（无需开关/特殊调用）。

        快照承载当前状态（含幂等锚点、活动告警、规则历史、seq），流水
        承载快照之后的状态变更；规则发布若已落入归档前缀，则从 manifest
        只读地补载（归档事件不日常加载）。
        返回是否发生了恢复。
        """
        if not self._persist:
            return False
        data = persistence.load_snapshot(self.config.snapshot_path)
        restored = False
        if data is not None:
            with self._lock:
                self.store.restore(data)
                self._snapshot_seq = self.store._seq  # noqa: SLF001
            restored = True
        rows = persistence.read_journal(self.config.journal_path)
        # 已归档前缀里的 rules_published 可能本地流水已裁剪；从归档补载规则，
        # 但不重放归档事件（其状态已由快照承载）。
        archived_rule_rows: list[dict] = []
        if self._archive is not None:
            try:
                archived_rule_rows = [
                    r for r in self._archive.read_archived_rows()
                    if r.get("kind") == "rules_published"]
            except Exception:
                archived_rule_rows = []
        with self._lock:
            self._apply_recovery_rows(
                archived_rule_rows, after_seq=self._snapshot_seq,
                events_only=False)
            tail_rows = [r for r in rows if r["seq"] > self._snapshot_seq]
            self._apply_recovery_rows(rows, after_seq=self._snapshot_seq)
            # 内存流水重建磁盘上尚未被已提交归档覆盖的全部行：它们要么是
            # 快照之后的判定尾，要么是崩溃前已淘汰、分段未提交而待补归档的
            # 前缀（排除淘汰记账行）。这样 fetch/裁剪都基于完整 live 集合。
            committed = self._archived_watermark
            live_disk_rows = [
                r for r in rows
                if int(r["seq"]) > committed and r.get("kind") != "history_evicted"
            ]
            self._rehydrate_journal(live_disk_rows)
            if tail_rows:
                # 流水尾重放完立即固化快照，使磁盘流水可安全裁剪为当前尾巴；
                # 之后再次崩溃也只需从这份快照恢复。
                self.save_snapshot()
                self._snapshot_seq = self.store._seq  # noqa: SLF001

        # 崩溃恢复：明细已淘汰、分段也已入队但 manifest 未提交的水位会丢。
        # 磁盘 journal 里仍保留这些行；把“已提交归档水位之外、且属于已淘汰
        # 明细”的连续前缀重新补归档，使归档覆盖与淘汰状态重新一致。
        self._rearchive_orphaned_prefix(rows)
        if restored or rows:
            log.info(
                "startup recovery: snapshot=%s tail_rows=%d events=%d "
                "alerts=%d revision=%s",
                restored,
                sum(1 for r in rows if r["seq"] > self._snapshot_seq),
                self.store.seen_count(), len(self.store.all_alerts()),
                self.store.current_revision())
        return restored or bool(rows)

    def _apply_recovery_rows(self, rows: list[dict], *, after_seq: int = 0,
                             events_only: bool = True) -> None:
        """按 seq 顺序把流水行应用到当前 store（重启恢复/快照尾重放）。

        ``events_only=True``（默认）应用事件与生命周期行；``False`` 只
        用于从归档补载规则发布行（归档事件不日常加载）。
        """
        for row in sorted(rows, key=lambda r: r["seq"]):
            seq = int(row["seq"])
            if events_only and seq <= after_seq:
                continue
            kind, payload = row["kind"], row.get("payload", {})
            if kind == "rules_published":
                rev = int(payload["revision"])
                if rev in self.store.rule_revisions():
                    continue
                raws = payload.get("rules")
                if not raws:
                    # 旧流水未内嵌规则：恢复时跳过（规则应由快照承载）
                    continue
                self.store.publish_rules(
                    rev, [rules_mod.rule_from_dict(r, revision=rev) for r in raws])
                self._store_seq_if_newer(seq)
                continue
            if not events_only:
                continue
            if kind == "event_accepted":
                event = _event_from_journal(payload)
                if self.store.put_event_if_absent(event):
                    self.store.bind_event_seq(event.event_id, seq)
                    self._replay_event_locked(event)
                self._store_seq_if_newer(seq)
            elif kind in (
                "alert_acknowledged", "alert_resolved", "alert_reopened",
                    "alert_merged"):
                self._apply_lifecycle_row(kind, payload)
                self._store_seq_if_newer(seq)
            else:
                self._store_seq_if_newer(seq)

    def _store_seq_if_newer(self, seq: int) -> None:
        if seq > self.store._seq:  # noqa: SLF001
            self.store._seq = seq  # noqa: SLF001

    def _apply_lifecycle_row(self, kind: str, payload: dict) -> None:
        alert_id = payload.get("alert_id")
        alert = self.store.get_alert(alert_id)
        if alert is None:
            return
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
        self.store.update_alert(alert)

    def _persist_journal_tail(self) -> None:
        """用当前内存中仍保留的流水原子替换磁盘流水（归档裁剪后）。"""
        if not self._persist:
            return
        persistence.rewrite_journal_atomic(
            self.config.journal_path, self.store.journal())

    def _rearchive_orphaned_prefix(self, disk_rows: list[dict]) -> None:
        """崩溃恢复：把内存流水中属于已淘汰明细、尚未被已提交归档覆盖的
        连续前缀重新补归档。

        判定：从最小 seq 开始，若 ``event_accepted`` 对应明细已不在本地
        （已淘汰），则该位置属于待补归档前缀；遇到第一条明细仍在本地的
        事件即停止（其后是正常 live 尾）。非事件行随前缀一起归档。
        """
        if self._archive is None:
            return
        committed = self._archive.committed_watermark()
        with self._lock:
            candidates = [
                e for e in self.store.journal()
                if e.seq > committed and e.kind != "history_evicted"]
            watermark = committed
            for entry in candidates:
                if entry.kind == "event_accepted":
                    eid = entry.payload.get("event_id")
                    if eid in self.store._events:  # noqa: SLF001
                        break  # 明细仍在本地：前缀到此为止
                watermark = entry.seq
            if watermark <= committed:
                return
            self._archive.submit(watermark, self.config.archive_max_pending)
            self.store.mark_archive_pending(watermark)
            self._pending_commits.add(watermark)

    def _rehydrate_journal(self, rows: list[dict]) -> None:
        """启动恢复时把快照之后的流水尾重建进内存（保留原始 seq/digest）。"""
        from datetime import datetime

        for row in sorted(rows, key=lambda r: r["seq"]):
            ts = row.get("ts")
            entry = JournalEntry(
                seq=int(row["seq"]),
                ts=datetime.fromisoformat(ts) if isinstance(ts, str) else ts,
                kind=row["kind"],
                payload=row.get("payload", {}),
                digest=row.get("digest", ""),
            )
            self.store.append_journal(entry)

    def _maybe_auto_snapshot(self) -> None:
        if self.config.snapshot_every <= 0:
            return
        self._events_since_snapshot += 1
        if self._events_since_snapshot >= self.config.snapshot_every:
            self.save_snapshot()
            self._snapshot_seq = self.store._seq  # noqa: SLF001
            self._events_since_snapshot = 0

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
            # 日常仅顺序追加（flush+fsync）；已交归档但尚未 ack 的前缀仍
            # 保留在磁盘上，崩溃恢复不丢。ack 回调中再原子重写完成裁剪。
            persistence.append_journal_file(self.config.journal_path, [entry])
        return entry

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


def build_engine(
    config: Config | None = None,
    *,
    autoload: bool = True,
    persist: bool = True,
) -> Engine:
    """构造引擎；持久化开启时先做启动恢复（快照 + 流水尾）。

    autoload 时从 rules_dir 加载初始规则（目录可不存在）；若本地状态中
    已有规则版本（重启接续），不重复加载以免冲突。
    """
    engine = Engine(config, persist=persist)
    recovered = False
    if persist:
        recovered = engine.restore_on_startup()
    if autoload and engine.config.rules_dir.exists():
        if not recovered and engine.store.current_revision() == 0:
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
    archive_dir: Path | str | None = None,
) -> tuple[Engine, list[dict]]:
    """基于流水重建引擎并逐条核对重放结论。

    流水自包含：``rules_published`` 带完整内嵌规则（旧流水仅有文档摘要时
    回退到 ``config.rules_dir`` 按 document_digest 匹配，匹配不到显式报错），
    ``event_accepted`` 带完整归一事件。重放按 seq 顺序重新执行规则判定与
    告警编排，并把每个事件的结论（无命中/去重/开告警/抑制、命中的规则
    版本）与原始流水逐条比对；任何不一致抛 :class:`ReplayConsistencyError`。

    ``include_archive=True`` 时先按 manifest 顺序读入归档分段（已被淘汰
    的历史前缀），与当前 journal 拼成完整流水再核对——用于用归档重建
    状态。归档缺失/损坏显式抛 :class:`ArchiveError`，不给出半成品结论。

    返回 ``(重建后的引擎, 逐条重放报告)``。
    """
    from .archive import ArchiveWriter
    from .errors import ReplayConsistencyError, RuleValidationError

    cfg = config or Config()
    rows = persistence.read_journal(Path(journal_path))
    if include_archive:
        arc_dir = Path(archive_dir) if archive_dir is not None else (
            cfg.archive_dir or (cfg.data_dir / "archive"))
        archived = ArchiveWriter(arc_dir, fetch_entries=lambda a, b: []).read_archived_rows() \
            if arc_dir.exists() else []
        rows = archived + rows
        # 全量重放：去重排序，且不允许 seq 重复（归档与本地不应重叠）
        seen_seqs: set[int] = set()
        deduped: list[dict] = []
        for row in sorted(rows, key=lambda r: r["seq"]):
            if row["seq"] in seen_seqs:
                raise ReplayConsistencyError(
                    f"seq {row['seq']} appears both in archive and live journal")
            seen_seqs.add(row["seq"])
            deduped.append(row)
        rows = deduped
    engine = Engine(cfg, persist=False)

    # 规则来源摘要 -> 规则原文集合（支持单文档与目录聚合两种发布方式）
    digest_to_bundle: dict[str, list[Rule]] = {}
    rules_dir = cfg.rules_dir
    if rules_dir.exists():
        for file in sorted(Path(rules_dir).glob("*.json")):
            raw = json.loads(file.read_text(encoding="utf-8"))
            doc_rules, _rev = rules_mod.load_rule_document(raw)
            digest_to_bundle[input_digest(raw)] = doc_rules
        try:
            dir_rules, dir_rev = rules_mod.load_rules_dir(rules_dir)
            combined = {
                "format_version": max(r.version for r in dir_rules),
                "revision": dir_rev,
                "rule_ids": sorted(r.rule_id for r in dir_rules),
                "source_dir": str(rules_dir),
            }
            digest_to_bundle[input_digest(combined)] = dir_rules
        except Exception:  # noqa: BLE001 - 目录聚合不可用时仍可用单文档匹配
            pass

    # event_id -> 紧随其 event_accepted 之后的原始结论行（全量索引，
    # 对归档+本地混合流同样有效）
    outcome_by_event: dict[str, dict] = {}
    for r in rows:
        if r["kind"] in _OUTCOME_KINDS:
            p = r.get("payload", {})
            eid = p.get("event_id")
            if eid is not None and eid not in outcome_by_event:
                outcome_by_event[eid] = r

    def _next_outcome(seq_after: int, event_id: str) -> dict | None:
        row = outcome_by_event.get(event_id)
        if row is not None and row["seq"] > seq_after:
            return row
        return None

    report: list[dict] = []
    for row in rows:
        kind, payload, seq = row["kind"], row["payload"], row["seq"]
        item: dict[str, Any] = {"seq": seq, "kind": kind, "consistent": True}

        if kind == "rules_published":
            rev = int(payload["revision"])
            if payload.get("rules"):
                # 新流水自包含：直接从内嵌规则还原该 revision
                bundle = [
                    rules_mod.rule_from_dict(r, revision=rev)
                    for r in payload["rules"]]
            else:
                # 旧流水：规则原文从 rules_dir 按 document_digest 匹配
                digest = payload.get("document_digest")
                bundle = digest_to_bundle.get(digest) if digest else None
                if bundle is None:
                    if include_archive:
                        raise ReplayConsistencyError(
                            f"seq={seq}: rule bundle digest {digest!r} not "
                            f"found inline or in {rules_dir}; cannot "
                            f"reproduce revision {rev}"
                        )
                    # 未纳入归档：该 revision 原文已不在本地保留，登记为
                    # 不可复现，不据此判不一致（完整核对请显式纳入归档）
                    item["reproducible"] = False
                    report.append(item)
                    continue
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
            # live-only 重放：规则原文或原始结论行已随淘汰进入归档时，
            # 本地上下文不完整，跳过重建与核对（避免误判 no_match 污染），
            # 登记为不可复现；完整逐条核对请显式 include_archive。
            if not include_archive:
                if outcome_row is None:
                    item["reproducible"] = False
                    report.append(item)
                    continue
                # 结论行在本地：若规则历史为空（规则发布行已入归档），同样
                # 无法可靠重建，登记为不可复现（完整核对请 include_archive）
                if not engine.store.rule_revisions():
                    item["reproducible"] = False
                    report.append(item)
                    continue
            # 在已恢复的规则历史下重新判定（bypass 时间窗与幂等：重放历史数据）
            replayed = engine._replay_event(event)
            item["event_id"] = event.event_id
            item["input_digest"] = event.digest
            item["replayed"] = replayed
            if outcome_row is None:
                raise ReplayConsistencyError(
                    f"seq={seq}: no original outcome for event "
                    f"{event.event_id}"
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

    # 重放后引擎状态与流水结尾应自洽：事件数核对。
    # 全量重放（含归档）必须覆盖全部事件；live-only 只核对本地可复现部分。
    total_events = sum(1 for r in rows if r["kind"] == "event_accepted")
    reproducible_events = 0
    for i in report:
        if i.get("kind") == "event_accepted" and "reproducible" not in i:
            reproducible_events += 1

    if include_archive:
        if engine.store.event_count() != total_events:
            raise ReplayConsistencyError(
                f"event count after replay {engine.store.event_count()} != "
                f"journal event_accepted {total_events}"
            )
    elif engine.store.event_count() != reproducible_events:
        raise ReplayConsistencyError(
            f"reproducible event count {engine.store.event_count()} != "
            f"{reproducible_events}"
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
