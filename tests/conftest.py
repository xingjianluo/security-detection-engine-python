import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# 单测日志中打印输入摘要与判定依据
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stdout,
)


BRUTE_RULES = {
    "format_version": 2,
    "revision": 1,
    "rules": [
        {
            "id": "brute", "event_type": "login", "severity": "high",
            "conditions": {"all": [
                {"field": "src_ip", "op": "prefix", "value": "10."}]},
            "correlation_key": ["src_ip", "user"],
            "merge_key": ["rule_id", "src_ip"],
            "suppress": {"window_s": 600, "max_severity": "medium"},
        },
        {
            "id": "probe", "event_type": "login", "severity": "low",
            "conditions": {"all": [
                {"field": "src_ip", "op": "prefix", "value": "10."}]},
            "correlation_key": ["src_ip", "user"],
            "merge_key": ["rule_id", "src_ip"],
        },
    ],
}


@pytest.fixture
def engine(tmp_path):
    from detector.config import Config
    from detector.engine import Engine

    cfg = Config(
        rules_dir=tmp_path / "rules",
        data_dir=tmp_path / "data",
        journal_path=tmp_path / "data" / "journal.jsonl",
        snapshot_path=tmp_path / "data" / "snapshot.json",
        future_tolerance_s=3600,
        max_inflight_events=100000,
    )
    eng = Engine(cfg)
    eng.publish_rules_document(BRUTE_RULES)
    return eng
