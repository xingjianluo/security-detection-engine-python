"""重放：流水重放结论与原始处理一致；每条判定可追溯规则版本与输入摘要。"""

import json
import logging
from datetime import timedelta

from detector.engine import replay
from detector.models import utcnow
from .helpers import event_payload, log_judgement

log = logging.getLogger("detector.tests")


def _feed(engine, now):
    events = [
        event_payload("r1", timestamp=now.isoformat()),
        event_payload("r2", timestamp=(now + timedelta(seconds=50)).isoformat()),
        event_payload("r3", severity="low", src_ip="10.5.5.5", user="x",
                      timestamp=(now + timedelta(seconds=60)).isoformat()),
        event_payload("r4", severity="critical", src_ip="10.6.6.6", user="y",
                      timestamp=(now + timedelta(seconds=70)).isoformat()),
        event_payload("r5",
                      timestamp=(now + timedelta(seconds=400)).isoformat()),
    ]
    for ev in events:
        result = engine.ingest_batch([ev], source="generic_json")
        log_judgement(ev, result)
    return events


def test_journal_replay_matches_original(tmp_path):
    from detector.config import Config
    from detector.engine import Engine
    from detector import persistence

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "rules.json"
    rule_file.write_text(json.dumps({
        "format_version": 2, "revision": 1, "rules": [
            {"id": "brute", "event_type": "login", "severity": "high",
             "conditions": {"all": [
                 {"field": "src_ip", "op": "prefix", "value": "10."}]},
             "correlation_key": ["src_ip", "user"],
             "merge_key": ["rule_id", "src_ip"],
             "suppress": {"window_s": 600, "max_severity": "medium"}},
            {"id": "probe", "event_type": "login", "severity": "low",
             "conditions": {"all": [
                 {"field": "src_ip", "op": "prefix", "value": "10."}]},
             "correlation_key": ["src_ip", "user"],
             "merge_key": ["rule_id", "src_ip"]},
        ]}))

    cfg = Config(
        rules_dir=rules_dir, data_dir=tmp_path / "data",
        journal_path=tmp_path / "data" / "journal.jsonl",
        future_tolerance_s=3600)
    engine = Engine(cfg, persist=True)
    engine.load_rules_from_dir()
    now = utcnow()
    _feed(engine, now)

    original = sorted(
        (a.alert_id, a.state.value, a.rule_id, a.rule_version,
         a.rule_revision, a.event_count, a.suppressed_by)
        for a in engine.list_alerts())
    original_events = engine.stats()["events"]

    replayed, report = replay(cfg.journal_path, cfg)
    for item in report:
        assert item["consistent"] is True, item

    replayed_alerts = sorted(
        (a.alert_id, a.state.value, a.rule_id, a.rule_version,
         a.rule_revision, a.event_count, a.suppressed_by)
        for a in replayed.list_alerts())
    assert replayed_alerts == original
    assert replayed.stats()["events"] == original_events

    # 每条事件判定可追溯到规则版本与输入摘要
    event_items = [r for r in report if r["kind"] == "event_accepted"]
    assert len(event_items) == original_events
    for item in event_items:
        assert item["input_digest"]
        assert item["original_kind"] in (
            "alert_opened", "alert_suppressed", "alert_dedup")
        if item["original_kind"] != "alert_dedup":
            assert item["rule_version"] == 2
            assert item["rule_revision"] == 1
    log.info("重放报告: %s",
             [(i["event_id"], i["original_kind"], i["input_digest"])
              for i in event_items])


def test_snapshot_roundtrip_then_tail_replay(engine):
    from detector.engine import replay_from_snapshot

    now = utcnow()
    engine._persist = True
    _feed(engine, now)
    snapshot_path = engine.save_snapshot()

    # 快照恢复后状态一致
    ok = engine.restore_snapshot(snapshot_path)
    assert ok
    events_before = engine.stats()["events"]

    # 快照+流水尾重放不报错（快照已含全部事件时尾为空）
    _eng2, report = replay_from_snapshot(
        snapshot_path, engine.config.journal_path, engine.config)
    assert isinstance(report, list)
    assert _eng2.stats()["events"] == events_before


def test_replay_detects_tampering(tmp_path):
    """输入摘要被篡改时重放必须显式报错，不给出静默结论。"""
    from detector.config import Config
    from detector.engine import Engine, replay
    from detector.errors import ReplayConsistencyError

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rules.json").write_text(json.dumps({
        "format_version": 2, "revision": 1, "rules": [
            {"id": "brute", "event_type": "login", "severity": "high",
             "conditions": {"all": [
                 {"field": "src_ip", "op": "prefix", "value": "10."}]}}]}))
    cfg = Config(rules_dir=rules_dir, data_dir=tmp_path / "data",
                 journal_path=tmp_path / "data" / "j.jsonl",
                 future_tolerance_s=3600)
    engine = Engine(cfg, persist=True)
    engine.load_rules_from_dir()
    engine.ingest_batch([event_payload("t1")], source="generic_json")

    rows = []
    for line in cfg.journal_path.read_text().splitlines():
        row = json.loads(line)
        if row["kind"] == "event_accepted":
            row["payload"]["digest"] = "deadbeefdeadbeef"
        rows.append(row)
    cfg.journal_path.write_text(
        "\n".join(json.dumps(r) for r in rows))

    try:
        replay(cfg.journal_path, cfg)
        raise AssertionError("篡改摘要后重放应失败")
    except ReplayConsistencyError as exc:
        assert "digest" in str(exc)
