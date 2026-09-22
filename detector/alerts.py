"""告警生命周期：去重、合并、抑制与状态机。

窗口语义（确定性，边界为半开区间 ``[start, start+window)``）：
- 去重：同一 ``correlation_key`` 在 ``dedup_window_s`` 内重复命中，
  不产生新告警，事件并入主告警（event_count 增加，但同 event_id 只计一次）。
- 合并：同 ``merge_key`` 的活动告警把后续命中并为主告警的事件流，
  被合并告警状态置 MERGED，``merged_into`` 指向主告警，可区分归属。
- 抑制：命中规则声明了 suppress 窗口时，窗口内严重度不高于
  ``suppress_max_severity`` 的新告警被压制为 SUPPRESSED，
  ``suppressed_by`` 指向压制者；**更高（含相等，严格更高才放行）
  严重度的告警绝不被吞**。

状态机：
    OPEN -> ACKNOWLEDGED -> RESOLVED（终态）
    OPEN/ACKNOWLEDGED/SUPPRESSED 之间按 LEGAL_TRANSITIONS 跳转
    任意活动态 -> MERGED（终态） / RESOLVED（终态）
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from .models import (
    Alert,
    AlertState,
    Event,
    MatchTrace,
    Rule,
    Severity,
    utcnow,
)

LEGAL_TRANSITIONS: dict[AlertState, frozenset[AlertState]] = {
    AlertState.OPEN: frozenset(
        {AlertState.ACKNOWLEDGED, AlertState.RESOLVED,
         AlertState.SUPPRESSED, AlertState.MERGED}
    ),
    AlertState.ACKNOWLEDGED: frozenset(
        {AlertState.RESOLVED, AlertState.SUPPRESSED,
         AlertState.OPEN, AlertState.MERGED}
    ),
    AlertState.SUPPRESSED: frozenset(
        {AlertState.OPEN, AlertState.RESOLVED,
         AlertState.ACKNOWLEDGED, AlertState.MERGED}
    ),
    AlertState.RESOLVED: frozenset(),
    AlertState.MERGED: frozenset(),
}


def transition(alert: Alert, target: AlertState) -> None:
    """就地执行状态跳转，非法跳转抛 IllegalTransitionError。"""
    from .errors import IllegalTransitionError

    if target == alert.state:
        return
    if target not in LEGAL_TRANSITIONS[alert.state]:
        raise IllegalTransitionError(
            f"illegal transition for alert {alert.alert_id}: "
            f"{alert.state.value} -> {target.value}",
            reason="illegal_state_transition",
        )
    alert.state = target
    alert.updated_at = utcnow()


def within_window(last_at: datetime, now: datetime, window_s: int) -> bool:
    """半开窗口：``last_at <= now < last_at + window_s``（正向判定）。

    跨窗口结论确定：恰好落在边界上的事件属于下一个窗口（产生新告警）。
    """
    delta = (now - last_at).total_seconds()
    return 0 <= delta < window_s


def _key(rule: Rule, event: Event, fields: list[str]) -> str:
    parts = []
    for field_name in fields:
        if field_name == "rule_id":
            parts.append(rule.rule_id)
        else:
            parts.append(f"{field_name}={getattr(event, field_name, None)!r}")
    return "|".join(parts)


def correlation_key_of(rule: Rule, event: Event) -> str:
    fields = rule.correlation_key or ["event_type"]
    return _key(rule, event, fields)


def merge_key_of(rule: Rule, event: Event) -> str:
    # 默认按规则合并
    fields = rule.merge_key or ["rule_id"]
    return _key(rule, event, fields)


def _alert_id(rule: Rule, event: Event, merge_key: str, corr_key: str) -> str:
    basis = f"{rule.rule_id}:{rule.revision}:{merge_key}:{corr_key}:{event.event_id}"
    return "al_" + hashlib.sha256(basis.encode()).hexdigest()[:16]


def make_alert(rule: Rule, event: Event, trace: MatchTrace) -> Alert:
    corr = correlation_key_of(rule, event)
    merge = merge_key_of(rule, event)
    now = utcnow()
    # 告警严重度 = max(规则基线, 事件严重度)：
    # 规则声明的是触发该规则的最低/基线级别，实际事件更严重时告警随之升级。
    severity = (
        rule.severity
        if rule.severity.rank >= event.severity.rank
        else event.severity
    )
    return Alert(
        alert_id=_alert_id(rule, event, merge, corr),
        rule_id=rule.rule_id,
        rule_version=rule.version,
        rule_revision=rule.revision,   # 绑定命中时规则版本
        correlation_key=corr,
        merge_key=merge,
        severity=severity,
        state=AlertState.OPEN,
        first_event_id=event.event_id,
        last_event_id=event.event_id,
        first_occurred_at=event.occurred_at,
        last_occurred_at=event.occurred_at,
        created_at=now,
        updated_at=now,
        event_count=1,
        event_digests=[event.digest],
        trace={
            "rule_name": rule.name,
            "checks": list(trace.checks),
            "input_digest": event.digest,
            "dedup_window_s": rule.dedup_window_s,
            "suppress_window_s": rule.suppress_window_s,
            "suppress_max_severity": (
                rule.suppress_max_severity.value
                if rule.suppress_max_severity else None
            ),
        },
    )


def should_dedup(alert: Alert, event: Event, rule: Rule) -> bool:
    """事件与主告警时间相关 -> 去重；已计入事件恒为去重（幂等）。

    - 正向：事件时间在 ``[first, first+dedup_window)`` 半开窗口内
      （锚定首事件，窗口不会被后续事件无限续用）；
    - 迟到/乱序：事件时间不早于首事件一个窗口宽度
      （``first - window <= event < first``），同样并入主告警，避免
      迟到事件产生错误的重复告警；
    - 恰好落在任一边界上的事件确定性地开启新窗口。
    """
    if event.digest in alert.event_digests:
        return True
    delta = (event.occurred_at - alert.first_occurred_at).total_seconds()
    return -rule.dedup_window_s <= delta < rule.dedup_window_s


def fold_event(alert: Alert, event: Event, trace: MatchTrace | None = None) -> bool:
    """把命中事件并入主告警。

    幂等：相同 event_id/digest 只计一次。返回是否实际计入。
    乱序安全：first/last 时间与事件 id 按实际值更新，不依赖到达顺序。
    """
    if event.digest in alert.event_digests:
        return False
    alert.event_digests.append(event.digest)
    alert.event_count += 1
    if event.occurred_at < alert.first_occurred_at:
        alert.first_occurred_at = event.occurred_at
        alert.first_event_id = event.event_id
    if event.occurred_at >= alert.last_occurred_at:
        alert.last_occurred_at = event.occurred_at
        alert.last_event_id = event.event_id
    alert.updated_at = utcnow()
    if trace is not None:
        alert.trace.setdefault("folded_checks", {})[event.event_id] = list(trace.checks)
    return True


def suppression_blocks(
    suppressor: Alert,
    candidate_severity: Severity,
    at: datetime,
) -> bool:
    """判定 ``at`` 时刻 suppressor 是否阻断 candidate。

    必须同时满足：
    - 落在半开抑制窗口内；
    - candidate 严重度不高于规则声明的上限 ``suppress_max_severity``；
    - candidate 严重度不高于压制者自身严重度
      —— 低优先级抑制绝不吞掉更高优先级的告警。
    """
    if suppressor.state.is_terminal or suppressor.merged_into:
        return False
    window_s = suppressor.trace.get("suppress_window_s", 0)
    max_sev_value = suppressor.trace.get("suppress_max_severity")
    if window_s <= 0 or max_sev_value is None:
        return False
    if not within_window(suppressor.last_occurred_at, at, window_s):
        return False
    if candidate_severity.rank > Severity(max_sev_value).rank:
        return False
    return candidate_severity.rank <= suppressor.severity.rank
