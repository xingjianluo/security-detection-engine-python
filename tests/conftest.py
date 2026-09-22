"""Shared fixtures and log capture so test logs contain input summaries and
decision rationales."""

from __future__ import annotations

import json
import logging
import os

import pytest

from detection.config import EngineConfig
from detection.service import DetectionService

# pytest --log-cli-level already attaches a handler to the root logger; we do
# not add another one (that would double every line). When running outside
# pytest (e.g. a script), ensure records still propagate to the root logger.


@pytest.fixture
def tmp_data_dir(tmp_path) -> str:
    return str(tmp_path / "data")


@pytest.fixture
def cfg(tmp_data_dir) -> EngineConfig:
    return EngineConfig(
        data_dir=tmp_data_dir,
        max_events_in_memory=1000,
        max_open_alerts=100,
    )


@pytest.fixture
def service(cfg: EngineConfig) -> DetectionService:
    svc = DetectionService(cfg=cfg)
    yield svc
    svc.close()


def write_rules(data_dir: str, rules: list[dict]) -> str:
    path = os.path.join(data_dir, "rules.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(rules, handle)
    return path


def log_case(name: str, payload: object, extra: str = "") -> None:
    """Print an input summary + decision basis for every test case."""
    summary = json.dumps(payload, ensure_ascii=False, default=str)
    if len(summary) > 300:
        summary = summary[:300] + "...(truncated)"
    logging.getLogger("tests").info("CASE %s | INPUT %s | %s", name, summary, extra)
