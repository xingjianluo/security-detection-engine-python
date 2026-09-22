"""可区分的错误分类。

所有拒绝都归类为 :class:`DetectionError` 的子类，调用方可据异常类型
（以及 ``reason`` 机器码）区分拒绝原因。
"""


class DetectionError(Exception):
    """引擎错误基类。"""

    reason: str = "detection_error"

    def __init__(self, message: str = "", *, reason: str | None = None) -> None:
        super().__init__(message or self.reason)
        if reason is not None:
            self.reason = reason


# ---- 事件摄入阶段 -------------------------------------------------------

class EventValidationError(DetectionError):
    """单条事件校验失败。"""

    reason = "event_validation_failed"


class MissingFieldError(EventValidationError):
    """必填字段缺失。"""

    reason = "missing_field"


class InvalidTimestampError(EventValidationError):
    """时间格式非法。"""

    reason = "invalid_timestamp"


class UnknownSourceError(EventValidationError):
    """事件来源格式未注册/不支持。"""

    reason = "unknown_source"


class BatchTooLargeError(DetectionError):
    """批次大小超过上限，整批拒绝（事务性，不产生部分写入）。"""

    reason = "batch_too_large"


class BatchOverSizeError(DetectionError):
    """批次序列化体积超过字节上限，整批拒绝。"""

    reason = "batch_oversize_bytes"


class BackpressureError(DetectionError):
    """积压超限，按策略拒绝。"""

    reason = "backpressure_rejected"


class DuplicateEventError(DetectionError):
    """幂等冲突：该事件标识已生效（用于显式区分重复投递）。"""

    reason = "duplicate_event"


# ---- 规则阶段 -----------------------------------------------------------

class RuleValidationError(DetectionError):
    """规则文件非法（结构、字段、版本）。"""

    reason = "rule_validation_failed"


class UnsupportedRuleVersionError(RuleValidationError):
    reason = "unsupported_rule_version"


class UnsupportedRuleFieldError(RuleValidationError):
    """规则含当前版本不支持的字段，必须显式拒绝而非忽略。"""

    reason = "unsupported_rule_field"


class UnsupportedRuleSemanticsError(RuleValidationError):
    """规则含不支持的操作符/语义。"""

    reason = "unsupported_rule_semantics"


# ---- 告警生命周期阶段 ----------------------------------------------------

class IllegalTransitionError(DetectionError):
    """告警状态机非法跳转。"""

    reason = "illegal_state_transition"


class StaleEventError(DetectionError):
    """迟到事件落在可接受窗口之外。"""

    reason = "stale_event"


class AlertNotFoundError(DetectionError):
    reason = "alert_not_found"


# ---- 持久化/重放阶段 -----------------------------------------------------

class SnapshotError(DetectionError):
    reason = "snapshot_error"


class ReplayConsistencyError(DetectionError):
    """重放结果与原始流水不一致。"""

    reason = "replay_mismatch"
