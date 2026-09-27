"""重启接续：相同启动方式（build_engine/create_app 默认 persist）下，
重启后历史事件/告警/规则版本/去重与抑制锚点继续生效；
重复投递仍判已处理；可随时对这段历史发起重放核对且结论一致。
"""

import json
import logging

import pytest

from detector.config import Config
from detector.engine import build_engine, replay
from detector.models import utcnow
from .helpers import event_payload, log_judgement

log = logging.getLogger("detector.tests")


@pytest.fixture
def cfg(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rules.json").write_text(json.dumps({
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
    return Config(rules_dir=rules_dir, data_dir=tmp_path / "data",
                  future_tolerance_s=3600, snapshot_every=5)


def _feed(engine, count=4):
    now = utcnow()
    results = []
    for i in range(count):
        ev = event_payload(f"r{i}", timestamp=now.isoformat())
        res = engine.ingest_batch([ev], source="generic_json")
        log_judgement(ev, [(a.outcome.value, a.dedup_hit) for a in res.accepted])
        results.append(res)
    return results


def test_restart_recovers_state_and_dedup(cfg):
    e1 = build_engine(cfg)
    _feed(e1)
    alert = e1.list_alerts()[0]
    e1.acknowledge(alert.alert_id)
    before = e1.stats()
    assert before["events"] == 4 and before["alerts"] >= 1

    # 模拟重启：相同启动方式，无额外开关
    e2 = build_engine(cfg)
    after = e2.stats()
    log.info("重启前 stats=%s 重启后 stats=%s", before, after)
    assert after["events"] == before["events"]
    assert after["alerts"] == before["alerts"]
    assert after["rule_revision"] == before["rule_revision"]
    # 告警状态延续（acknowledged 不丢）
    recovered = e2.get_alert(alert.alert_id)
    assert recovered is not None
    assert recovered.state.value == "acknowledged"
    assert recovered.event_count == alert.event_count

    # 重复投递重启前已处理的事件：仍判已处理，不重复计数/开告警
    dup = event_payload("r0", timestamp=utcnow().isoformat())
    res = e2.ingest_batch([dup], source="generic_json")
    log_judgement(dup, [(a.outcome.value, a.dedup_hit) for a in res.accepted])
    assert res.accepted[0].dedup_hit is True
    assert e2.stats()["events"] == before["events"]
    assert len(e2.list_alerts()) == before["alerts"]


def test_restart_keeps_suppression_anchor(cfg):
    """抑制锚点（高严重度告警的抑制窗口）重启后继续生效。"""
    e1 = build_engine(cfg)
    now = utcnow()
    # 高严重度事件开 suppressor 告警
    e1.ingest_batch([event_payload("s1", timestamp=now.isoformat())],
                    source="generic_json")
    # 低严重度事件被抑制（probe 规则 low <= medium）
    e1.ingest_batch([event_payload("s2", severity="low", user="mallory",
                                   timestamp=now.isoformat())],
                    source="generic_json")
    suppressed = [a for a in e1.list_alerts() if a.state.value == "suppressed"]
    assert suppressed, "低优先级告警应被抑制"

    e2 = build_engine(cfg)
    # 重启后再来一个低严重度事件：仍应被抑制（抑制窗口锚点延续）
    res = e2.ingest_batch([event_payload("s3", severity="low", user="mallory",
                                         timestamp=now.isoformat())],
                          source="generic_json")
    log_judgement("s3", [(a.outcome.value, a.dedup_hit) for a in res.accepted])
    states = {a.state.value for a in e2.list_alerts()}
    assert "suppressed" in states


def test_restart_then_replay_matches_original(cfg):
    """重启之后仍可针对这段历史发起重放核对，结论与当初一致。"""
    e1 = build_engine(cfg)
    _feed(e1, count=5)

    # 重启（写一次快照再走恢复路径）
    e1.save_snapshot()
    e2 = build_engine(cfg)
    e2.ingest_batch([event_payload("post-restart",
                                   timestamp=utcnow().isoformat())],
                    source="generic_json")
    live = sorted(
        (a.alert_id, a.state.value, a.rule_id, a.rule_version,
         a.rule_revision, a.event_count, a.suppressed_by)
        for a in e2.list_alerts())

    eng, report = replay(cfg.journal_path, cfg)
    for item in report:
        assert item["consistent"] is True, item
    event_items = [r for r in report if r["kind"] == "event_accepted"]
    # 每条判定可追溯到输入摘要与规则版本
    for item in event_items:
        assert item["input_digest"]
        if item["original_kind"] in ("alert_opened", "alert_suppressed"):
            assert item["rule_revision"] >= 1
    log.info("重放核对: %s",
             [(i["event_id"], i["original_kind"]) for i in event_items])
    # 重放重建的结论与重启后实时状态逐条一致
    replayed = sorted(
        (a.alert_id, a.state.value, a.rule_id, a.rule_version,
         a.rule_revision, a.event_count, a.suppressed_by)
        for a in eng.list_alerts())
    assert replayed == live
    assert eng.stats()["events"] == e2.stats()["events"]


def test_restart_with_snapshot_every_covers_tail(cfg):
    """snapshot_every 自动快照 + 流水尾恢复：重启后 seq 单调、流水连续。"""
    e1 = build_engine(cfg)
    _feed(e1, count=6)  # snapshot_every=5，期间会自动落快照
    assert cfg.snapshot_path.exists()
    seq_before = e1.store.next_seq()

    e2 = build_engine(cfg)
    # seq 不回退（重启后续写的流水序号不复用、不冲突）
    assert e2.store.next_seq() >= seq_before
    assert e2.stats()["events"] == 6
