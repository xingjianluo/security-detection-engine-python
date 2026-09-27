"""统一事件/告警模型。

外部多来源事件先归一为 :class:`Event`，检测命中后产出 :class:`Alert`，
每条告警保存全部判定依据（规则版本、输入摘要），以支持可解释与可追溯。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class AlertState(str, Enum):
    OPEN = "open"
    SUPPRESSED = "suppressed"   # 被更高优先级告警的抑制窗口压制
    MERGED = "merged"           # 被合并进主告警
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"

    @property
    def is_terminal(self) -> bool:
        return self in (AlertState.RESOLVED, AlertState.MERGED)


class EventOutcome(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


_ISO_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
)


def parse_ts(value: Any) -> datetime:
    """把多种时间表达解析为带时区的 UTC ``datetime``。

    支持：ISO-8601（含 ``Z`` 与偏移量）、unix epoch（int/float，秒）、
    常见空格分隔格式。无法解析或类型非法时抛 :class:`ValueError`，
    由 normalize 层归类为 InvalidTimestampError。
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(f"unsupported timestamp type: {type(value).__name__}")
    elif isinstance(value, (int, float)):
        number = float(value)
        # 确定性单位识别：秒级时间戳到 2286 年都 < 1e11；
        # >= 1e12 视为毫秒，>= 1e15 视为微秒。
        abs_n = abs(number)
        if abs_n >= 1e15:
            number /= 1_000_000.0
        elif abs_n >= 1e12:
            number /= 1000.0
        try:
            dt = datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError(f"epoch out of range: {value!r}") from exc
    else:
        text = value.strip()
        if not text:
            raise ValueError("empty timestamp")
        # 纯数字字符串按 epoch 处理
        if text.lstrip("-").replace(".", "", 1).isdigit():
            return parse_ts(float(text))
        dt = None
        for fmt in _ISO_FORMATS:
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            try:
                dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(f"unparseable timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def input_digest(payload: Any) -> str:
    """计算原始输入的稳定摘要（SHA-256, 前 16 位）。"""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class Event:
    """归一化后的统一事件。"""

    event_id: str                     # 外部来源的唯一标识（幂等键）
    source: str                       # 来源格式名：syslog_cef / generic_json / ...
    event_type: str
    severity: Severity
    occurred_at: datetime              # 事件实际发生时间（UTC）
    ingested_at: datetime              # 引擎接收时间（UTC）
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    host: str | None = None
    action: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "occurred_at": self.occurred_at.isoformat(),
            "ingested_at": self.ingested_at.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "user": self.user,
            "host": self.host,
            "action": self.action,
            "raw": self.raw,
            "digest": self.digest,
        }


@dataclass
class EventResult:
    """单条事件的摄入结论。"""

    event_id: str
    outcome: EventOutcome
    digest: str = ""
    reason: str | None = None         # 拒绝原因机器码
    detail: str = ""                  # 人类可读细节
    dedup_hit: bool = False           # True 表示为重复投递，沿用既有结论


@dataclass
class BatchResult:
    """整批结论：校验失败的批次整体拒绝，不产生部分写入。"""

    accepted: list[EventResult] = field(default_factory=list)
    rejected: list[EventResult] = field(default_factory=list)
    batch_rejected: bool = False
    batch_reason: str | None = None
    # 有界保留：本批处理过程中触发的最旧淘汰条数（policy=evict_oldest）
    evicted: int = 0
    # 容量水位（便于调用方判断离上限还有多远）
    retained_records: int = 0
    retained_bytes: int = 0


@dataclass(frozen=True)
class Rule:
    """检测规则（归一后的内部表示）。

    ``version`` 为规则格式版本（1 或 2）；``revision`` 为规则内容版本号，
    每次规则集发布单调递增，告警绑定命中时刻的 revision 以保证复现。
    """

    rule_id: str
    version: int
    revision: int
    name: str
    event_type: str
    conditions: dict[str, Any]         # 归一化后的匹配条件
    severity: Severity
    dedup_window_s: int = 300
    suppress_window_s: int = 0         # 命中后抑制低优先级告警的窗口
    suppress_max_severity: Severity | None = None
    correlation_key: list[str] = field(default_factory=list)
    merge_key: list[str] = field(default_factory=list)  # 同 key 告警合并
    enabled: bool = True


@dataclass
class MatchTrace:
    """规则判定依据（可解释）。"""

    matched: bool
    rule_id: str
    rule_version: int
    rule_revision: int
    checks: list[str] = field(default_factory=list)


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    rule_version: int
    rule_revision: int                 # 绑定命中时规则版本，更新不改写
    correlation_key: str
    merge_key: str
    severity: Severity
    state: AlertState
    first_event_id: str
    last_event_id: str
    first_occurred_at: datetime
    last_occurred_at: datetime
    created_at: datetime
    updated_at: datetime
    event_count: int = 1
    # 被合并/抑制的归属关系
    merged_into: str | None = None
    suppressed_by: str | None = None
    # 可追溯
    event_digests: list[str] = field(default_factory=list)
    trace: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "rule_revision": self.rule_revision,
            "correlation_key": self.correlation_key,
            "merge_key": self.merge_key,
            "severity": self.severity.value,
            "state": self.state.value,
            "first_event_id": self.first_event_id,
            "last_event_id": self.last_event_id,
            "first_occurred_at": self.first_occurred_at.isoformat(),
            "last_occurred_at": self.last_occurred_at.isoformat(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "event_count": self.event_count,
            "merged_into": self.merged_into,
            "suppressed_by": self.suppressed_by,
            "event_digests": list(self.event_digests),
            "trace": self.trace,
        }


@dataclass
class JournalEntry:
    """流水条目：引擎所有状态变更均先写流水（append-only）。"""

    seq: int
    ts: datetime
    kind: str                           # event_accepted / rule_published / alert_*
    payload: dict[str, Any]
    digest: str = ""


def now_iso() -> str:
    return utcnow().isoformat()
