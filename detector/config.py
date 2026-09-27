"""引擎配置项。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# 内置默认路径（用于识别调用方是否显式覆盖）
_DEFAULT_DATA_DIR = Path("data")
_DEFAULT_JOURNAL = Path("data/journal.jsonl")
_DEFAULT_SNAPSHOT = Path("data/snapshot.json")


@dataclass(frozen=True)
class Config:
    # 摄入限制
    max_batch_size: int = 1000             # 单批事件条数上限
    max_batch_bytes: int = 2 * 1024 * 1024  # 单批字节上限
    max_event_bytes: int = 64 * 1024

    # 背压：待处理事件积压上限，超限按 on_backpressure 策略处置
    max_inflight_events: int = 10_000
    on_backpressure: str = "reject"        # reject | delay

    # 迟到/乱序
    max_out_of_order_s: int = 3600         # 可接受的迟到窗口
    future_tolerance_s: int = 300          # 允许的时钟漂移

    # 告警窗口
    default_dedup_window_s: int = 300
    default_suppress_window_s: int = 0

    # 规则
    supported_rule_versions: tuple[int, ...] = (1, 2)
    rules_dir: Path = Path("rules")
    data_dir: Path = Path("data")

    # 持久化/重放（persist=True 时启动自动从 快照+流水 恢复，无需额外开关）
    persist: bool = True
    journal_path: Path = Path("data/journal.jsonl")
    snapshot_path: Path = Path("data/snapshot.json")
    snapshot_every: int = 1000             # 每 N 条流水自动落一次快照（0 关闭）

    # 有界保留（0 表示不限制）；超限按 on_retention_exceeded 策略处置
    max_retained_events: int = 0           # 本地保留的事件明细上限（条）
    max_retained_alerts: int = 0           # 本地保留的告警明细上限（条）
    max_retained_journal: int = 0          # 本地保留的判定流水上限（条）
    on_retention_exceeded: str = "evict"   # evict（淘汰最旧） | reject（拒绝新进入）

    # 归档：被淘汰的历史落入本地归档，日常查询不加载，可显式纳入重放
    archive_enabled: bool = True
    archive_dir: Path = Path("data/archive")

    def __post_init__(self) -> None:
        # data_dir 被显式覆盖而持久化路径仍为内置默认时，
        # 把持久化路径锚定到 data_dir 下，避免不同实例互相污染。
        if self.data_dir != _DEFAULT_DATA_DIR:
            if self.journal_path == _DEFAULT_JOURNAL:
                object.__setattr__(
                    self, "journal_path", self.data_dir / "journal.jsonl")
            if self.snapshot_path == _DEFAULT_SNAPSHOT:
                object.__setattr__(
                    self, "snapshot_path", self.data_dir / "snapshot.json")
            if self.archive_dir == _DEFAULT_DATA_DIR / "archive":
                object.__setattr__(
                    self, "archive_dir", self.data_dir / "archive")
