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
    snapshot_every: int = 1000
