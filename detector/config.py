"""引擎配置项。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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

    # 持久化/重放
    journal_path: Path = Path("data/journal.jsonl")
    snapshot_path: Path = Path("data/snapshot.json")
    snapshot_every: int = 1000          # 每处理 N 条事件自动落一次快照

    # 有界保留：本地历史明细（归一事件明细 + 已终态告警明细 + 流水明细）
    # 的总量上限。命中任一上限时按 retention_policy 处置。
    # 幂等锚点（event_id 摘要）、去重/抑制锚点（活动告警）不受淘汰影响。
    retention_max_records: int = 100_000   # 保留明细条数上限（事件+终态告警+流水）
    retention_max_bytes: int = 64 * 1024 * 1024  # 保留明细序列化字节上限
    # reject_new：容量满时拒绝新进入（原因码 retention_full，整批事务性拒绝）
    # evict_oldest：先把最旧明细归档（archive），再淘汰，保持当前状态一致
    retention_policy: str = "evict_oldest"

    # 归档：被淘汰明细的长期本地留存（JSONL 分段 + manifest）。
    # 日常查询/运行不加载归档；仅显式重放/重建时纳入。
    archive_enabled: bool = True
    # None 表示 data_dir/archive；显式给定时按给定路径
    archive_dir: Path | None = None
    archive_max_pending: int = 8        # 待归档目标积压上限；满则拒绝新摄入
