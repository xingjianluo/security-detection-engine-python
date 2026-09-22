"""Local file paths and resource limits for the detection engine."""

from __future__ import annotations

import dataclasses
import os


@dataclasses.dataclass(frozen=True)
class EngineConfig:
    data_dir: str = dataclasses.field(
        default_factory=lambda: os.environ.get("DETECTION_DATA_DIR", "data"))
    rules_file: str = "rules.json"
    snapshot_file: str = "snapshot.json"
    journal_file: str = "journal.log"
    max_event_bytes: int = 65536
    max_batch_events: int = 1000
    max_batch_bytes: int = 4 * 1024 * 1024
    max_events_in_memory: int = 100_000
    max_open_alerts: int = 10_000
    late_event_horizon_seconds: float = 24 * 3600.0
    default_dedupe_window_seconds: int = 300
