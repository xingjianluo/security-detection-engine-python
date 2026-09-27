"""重启接续：用相同启动方式（build_engine/create_app persist=True）重建后，
事件、告警、规则版本、去重与抑制锚点都能继续查询并参与判定；重复投递
仍判已处理；归档后的历史也可随时重放核对，结论与当初一致。
"""

import json
import logging
from datetime import timedelta
from pathlib import Path

from detector.config import Config
from detector.engine import build_engine, replay
from detector.models import utcnow
from .helpers import event_payload, log_judgement

log = logging.getLogger("detector.tests")


def _cfg(tmp_path: Path) -> Config:
    d = tmp_path / "data"
    return Config(
        rules_dir=tmp_path / "rules", data_dir=d,
        journal_path=d / "journal.jsonl", snapshot_path=d / "snapshot.json",
        archive_dir=d / "archive", future_tolerance_s=3600,
        snapshot_every=0)


def _rules():
    from .conftest import BRUTE_RULES
    return BRUTE_RULES


def _feed(engine, now):
    p1 = event_payload("c1", timestamp=now.isoformat())
    p2 = event_payload("c2",
                       timestamp=(now + timedelta(seconds=50)).isoformat())
    p3 = event_payload("c3", severity="low", src_ip="10.9.9.9", user="z",
                       timestamp=(now + timedelta(seconds=60)).isoformat())
    for p in (p1, p2, p3):
        r = engine.ingest_batch([p], source="generic_json")
        log_judgement(p, r)
    return [p1, p2, p3]


def test_restart_restores_state_and_dedup(tmp_path):
    cfg = _cfg(tmp_path)
    eng = build_engine(cfg, persist=True)
    assert eng.publish_rules_document(_rules()) == 1
    now = utcnow()
    _feed(eng, now)
    before = {
        "events": eng.stats()["events"],
        "alerts": sorted(
            (a.alert_id, a.state.value, a.rule_revision, a.event_count,
             a.suppressed_by) for a in eng.list_alerts()),
        "revision": eng.store.current_revision(),
    }

    # 相同启动方式重新构建（模拟进程重启）：自动恢复，无特殊调用
    eng2 = build_engine(cfg, persist=True)
    assert eng2.stats()["events"] == before["events"]
    assert eng2.store.current_revision() == before["revision"]
    assert sorted(
        (a.alert_id, a.state.value, a.rule_revision, a.event_count,
         a.suppressed_by) for a in eng2.list_alerts()) == before["alerts"]
    assert eng2.get_event("c1") is not None

    # 重启后重复投递历史事件 -> 仍判重，不重复计数/告警
    r = eng2.ingest_batch(
        [event_payload("c1", timestamp=now.isoformat())],
        source="generic_json")
    assert r.accepted[0].dedup_hit is True
    assert eng2.stats()["events"] == before["events"]

    # 重启后去重锚点仍生效：同窗口新帧折叠进既有告警，而非新开
    p_new = event_payload(
        "c4", timestamp=(now + timedelta(seconds=10)).isoformat())
    r2 = eng2.ingest_batch([p_new], source="generic_json")
    log_judgement(p_new, r2)
    assert r2.accepted[0].dedup_hit is False
    brute = [a for a in eng2.list_alerts() if a.rule_id == "brute"][0]
    assert brute.event_count == 3  # c1,c2,c4（重启前 2 + 重启后 1）

    # 抑制锚点仍在：再投低优先级不同源（在抑制者最近事件窗口内）-> 仍抑制
    p5 = event_payload("c5", severity="low", src_ip="10.7.7.7", user="q",
                       timestamp=(now + timedelta(seconds=55)).isoformat())
    eng2.ingest_batch([p5], source="generic_json")
    assert any(a.state.value == "suppressed" and a.last_event_id == "c5"
               for a in eng2.list_alerts())


def test_restart_then_replay_matches_original(tmp_path):
    cfg = _cfg(tmp_path)
    eng = build_engine(cfg, persist=True)
    eng.publish_rules_document(_rules())
    now = utcnow()
    _feed(eng, now)
    original_alerts = sorted(
        (a.alert_id, a.state.value, a.rule_id, a.rule_version,
         a.rule_revision, a.event_count, a.suppressed_by)
        for a in eng.list_alerts())
    original_events = eng.stats()["events"]

    # 重启后随时可针对这段历史发起重放核对（只读本地 journal，不依赖归档）
    replayed, report = replay(cfg.journal_path, cfg)
    assert all(i["consistent"] for i in report)
    assert sorted(
        (a.alert_id, a.state.value, a.rule_id, a.rule_version,
         a.rule_revision, a.event_count, a.suppressed_by)
        for a in replayed.list_alerts()) == original_alerts
    assert replayed.stats()["events"] == original_events
    for item in report:
        if "input_digest" in item:
            assert item["input_digest"]
            assert item["original_kind"] in (
                "alert_opened", "alert_suppressed", "alert_dedup")


def test_restart_after_terminal_lifecycle(tmp_path):
    """resolve/merge 等终态变更在重启后保持（流水尾恢复）。"""
    cfg = _cfg(tmp_path)
    eng = build_engine(cfg, persist=True)
    eng.publish_rules_document(_rules())
    now = utcnow()
    _feed(eng, now)
    aid = [a for a in eng.list_alerts() if a.rule_id == "brute"][0].alert_id
    eng.resolve(aid)

    eng2 = build_engine(cfg, persist=True)
    assert eng2.get_alert(aid).state.value == "resolved"
