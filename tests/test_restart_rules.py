"""重启时的规则加载/版本语义与非法配置失败边界。

覆盖：
- 规则内容变化后以相同启动方式重启 -> 自动发布新版本并立即参与判定，
  历史告警仍绑定命中时的旧版本，不被改写；
- 规则内容不变重启 -> 当前生效 revision 保持不变、不多发版本；
- 规则配置非法（坏 JSON）/只写了一半（部分文件非法）-> 启动阶段显式
  报错，原有可用状态（事件/告警/规则版本）保持不变，既不静默沿用旧
  规则，也不留半套规则；
- 不同 data_dir 的实例本地持久化互不串数据，重启后各自回到同一份状态。
"""

import json
import logging
from pathlib import Path

import pytest

from detector.config import Config
from detector.engine import build_engine
from detector.errors import RuleValidationError
from detector.models import utcnow

log = logging.getLogger("detector.tests")


def _rule_doc(prefix: str, *, revision: int = 1) -> dict:
    """src_ip 前缀命中规则；merge/correlation 含 src_ip，不同源各开各告警。"""
    return {"format_version": 2, "revision": revision, "rules": [
        {"id": "brute", "event_type": "login", "severity": "high",
         "conditions": {"all": [
             {"field": "src_ip", "op": "prefix", "value": prefix}]},
         "correlation_key": ["src_ip", "user"],
         "merge_key": ["rule_id", "src_ip"]}]}


def _cfg(base: Path) -> Config:
    d = base / "data"
    return Config(
        rules_dir=base / "rules", data_dir=d,
        journal_path=d / "journal.jsonl", snapshot_path=d / "snapshot.json",
        archive_dir=d / "archive", future_tolerance_s=3600, snapshot_every=0)


def _event(eid: str, ip: str, *, ts: str | None = None) -> dict:
    return {"event_id": eid, "type": "login", "severity": "high",
            "timestamp": ts or utcnow().isoformat(),
            "src_ip": ip, "user": "bob"}


def _write_rules(base: Path, doc: dict, name: str = "rules.json") -> None:
    rdir = base / "rules"
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / name).write_text(json.dumps(doc), encoding="utf-8")


def test_changed_rules_take_effect_on_restart(tmp_path):
    _write_rules(tmp_path, _rule_doc("10."))
    eng = build_engine(_cfg(tmp_path), persist=True)
    assert eng.store.current_revision() == 1

    ts = utcnow().isoformat()
    eng.ingest_batch([_event("e1", "10.0.0.1", ts=ts)], source="generic_json")
    old_alerts = eng.list_alerts()
    assert len(old_alerts) == 1
    old_alert = old_alerts[0]
    assert old_alert.rule_revision == 1

    # 以相同启动方式重启：规则内容未变 -> revision 不变、不多发版本
    eng = build_engine(_cfg(tmp_path), persist=True)
    assert eng.store.current_revision() == 1
    assert eng.store.rule_revisions() == [1]

    # 改写磁盘规则：新规则只命中 192.168.* 网段，再按相同方式重启
    _write_rules(tmp_path, _rule_doc("192.168."))
    eng = build_engine(_cfg(tmp_path), persist=True)
    assert eng.store.current_revision() == 2, eng.store.current_revision()
    assert eng.store.rule_revisions() == [1, 2]

    # 历史告警继续绑定 revision 1，不被新规则改写
    assert eng.get_alert(old_alert.alert_id).rule_revision == 1

    # 新规则立即参与判定：旧网段事件不再触发告警
    before = len(eng.list_alerts())
    eng.ingest_batch([_event("e2", "10.0.0.2", ts=ts)], source="generic_json")
    assert len(eng.list_alerts()) == before
    # 新网段事件命中 revision 2 并开新告警
    eng.ingest_batch([_event("e3", "192.168.0.1", ts=ts)], source="generic_json")
    alerts = eng.list_alerts()
    new_alert = next(a for a in alerts if a.first_event_id == "e3")
    assert new_alert.rule_revision == 2
    log_alert_revisions(alerts)

    # 再次重启（规则没变）-> revision 仍是 2，不产生 revision 3
    eng = build_engine(_cfg(tmp_path), persist=True)
    assert eng.store.current_revision() == 2
    assert eng.store.rule_revisions() == [1, 2]
    # 历史事件幂等、历史告警绑定都还在
    r = eng.ingest_batch([_event("e1", "10.0.0.1", ts=ts)],
                         source="generic_json")
    assert r.accepted[0].dedup_hit is True
    assert eng.get_alert(old_alert.alert_id).rule_revision == 1

    # 跨版本历史仍可重放核对：rev1 事件/告警、rev2 事件/告警逐条一致
    from detector.engine import replay

    _replayed, report = replay(eng.config.journal_path, eng.config)
    outcome_items = [i for i in report if "original_kind" in i]
    assert outcome_items
    for item in outcome_items:
        assert item["consistent"] is True, item
    log.info("跨版本重放通过: %d 条结论全部一致", len(outcome_items))


def test_declared_revision_bump_without_content_change_publishes_nothing(tmp_path):
    """只改文件里的 revision 编号、规则内容不变 -> 同一 revision，不多发。"""
    _write_rules(tmp_path, _rule_doc("10.", revision=1))
    build_engine(_cfg(tmp_path), persist=True)
    _write_rules(tmp_path, _rule_doc("10.", revision=42))
    eng = build_engine(_cfg(tmp_path), persist=True)
    assert eng.store.current_revision() == 1
    assert eng.store.rule_revisions() == [1]


def test_malformed_rules_fail_startup_and_preserve_state(tmp_path):
    _write_rules(tmp_path, _rule_doc("10."))
    eng = build_engine(_cfg(tmp_path), persist=True)
    ts = utcnow().isoformat()
    eng.ingest_batch([_event("e1", "10.0.0.1", ts=ts)], source="generic_json")
    assert len(eng.list_alerts()) == 1
    eng.save_snapshot()
    snapshot_bytes = (tmp_path / "data" / "snapshot.json").read_bytes()
    journal_text = (tmp_path / "data" / "journal.jsonl").read_text()

    # 坏 JSON：启动阶段必须显式报错
    (tmp_path / "rules" / "rules.json").write_text("{ broken json", encoding="utf-8")
    with pytest.raises(RuleValidationError):
        build_engine(_cfg(tmp_path), persist=True)
    # 失败启动没有改写原有快照/流水
    assert (tmp_path / "data" / "snapshot.json").read_bytes() == snapshot_bytes
    assert (tmp_path / "data" / "journal.jsonl").read_text() == journal_text

    # 只写了一半：一个好文件 + 一个非法文件（未知字段）-> 整批失败，
    # 不能加载半套规则
    _write_rules(tmp_path, _rule_doc("172."), name="a_good.json")
    (tmp_path / "rules" / "rules.json").unlink()
    _write_rules(tmp_path,
                 {"format_version": 2, "revision": 9, "rules": [
                     {"id": "half", "event_type": "login", "severity": "high",
                      "totally_unknown": 1}]},
                 name="z_bad.json")
    with pytest.raises(RuleValidationError):
        build_engine(_cfg(tmp_path), persist=True)
    # 半套配置的失败同样不破坏原有持久化状态
    assert (tmp_path / "data" / "snapshot.json").read_bytes() == snapshot_bytes
    assert (tmp_path / "data" / "journal.jsonl").read_text() == journal_text

    # 失败后原有可用状态没有被破坏：修复磁盘配置后以相同方式重启，
    # 恢复到原有状态（revision 1、历史事件/告警仍在），且没有半成品版本
    (tmp_path / "rules" / "z_bad.json").unlink()
    eng = build_engine(_cfg(tmp_path), persist=True)
    # a_good.json 内容（172. 网段）与原 revision 1（10.）不同 -> 正常发布 rev 2
    assert eng.store.rule_revisions() == [1, 2]
    assert eng.store.current_revision() == 2
    assert eng.stats()["events"] == 1
    assert len(eng.list_alerts()) == 1
    # 只有一个“好规则文件”，没有残留半套规则
    assert sorted(r.rule_id for r in eng.store.active_rules()) == ["brute"]
    # 失败期间快照始终可读且未被破坏
    assert (tmp_path / "data" / "snapshot.json").read_bytes() != b""
    assert snapshot_bytes is not None


def test_distinct_data_dirs_do_not_share_persistence(tmp_path):
    """只配 data_dir（不显式给 journal/snapshot 路径）也必须各写各的目录。"""
    for tag, ip in (("instX", "10.1.1.1"), ("instY", "10.2.2.2")):
        base = tmp_path / tag
        _write_rules(base, _rule_doc("10."))
        cfg = Config(rules_dir=base / "rules", data_dir=base / "data",
                     archive_dir=base / "data" / "archive",
                     future_tolerance_s=3600, snapshot_every=0)
        # 未显式指定路径 -> 默认跟随 data_dir
        assert cfg.journal_path == base / "data" / "journal.jsonl"
        assert cfg.snapshot_path == base / "data" / "snapshot.json"
        eng = build_engine(cfg, persist=True)
        ts = utcnow().isoformat()
        eng.ingest_batch([_event(f"{tag}-e1", ip, ts=ts)],
                         source="generic_json")
        # 持久化流水确实落在各自 data_dir
        assert (base / "data" / "journal.jsonl").exists()
        text = (base / "data" / "journal.jsonl").read_text()
        assert f"{tag}-e1" in text
        # 另一份 data_dir 不含本实例数据
        other = tmp_path / ("instY" if tag == "instX" else "instX") / "data"
        if (other / "journal.jsonl").exists():
            assert f"{tag}-e1" not in (other / "journal.jsonl").read_text()

    # 重启各自实例：只看到投给它自己的数据，互不串
    cx = Config(rules_dir=tmp_path / "instX" / "rules",
                data_dir=tmp_path / "instX" / "data",
                archive_dir=tmp_path / "instX" / "data" / "archive",
                future_tolerance_s=3600, snapshot_every=0)
    cy = Config(rules_dir=tmp_path / "instY" / "rules",
                data_dir=tmp_path / "instY" / "data",
                archive_dir=tmp_path / "instY" / "data" / "archive",
                future_tolerance_s=3600, snapshot_every=0)
    ex = build_engine(cx, persist=True)
    ey = build_engine(cy, persist=True)
    assert ex.get_event("instX-e1") is not None
    assert ex.get_event("instY-e1") is None
    assert ey.get_event("instY-e1") is not None
    assert ey.get_event("instX-e1") is None
    assert ex.stats()["events"] == 1 and ey.stats()["events"] == 1
    assert len(ex.list_alerts()) == 1 and len(ey.list_alerts()) == 1
    # 归档目录也各自独立
    assert ex.config.archive_dir == tmp_path / "instX" / "data" / "archive"


def test_restart_revision_advances_safely_with_gaps_and_stale_declaration(tmp_path):
    """历史 revision 因文件声明值出现跳跃（1,2,99）后，下一次内容变化仍能
    安全推进到 100；声明值停在旧值（99）也不会撞车或覆盖历史。"""
    _write_rules(tmp_path, _rule_doc("10.", revision=1))
    assert build_engine(_cfg(tmp_path), persist=True).store.current_revision() == 1
    _write_rules(tmp_path, _rule_doc("172.", revision=1))  # 声明值落后 -> rev 2
    assert build_engine(_cfg(tmp_path), persist=True).store.current_revision() == 2
    _write_rules(tmp_path, _rule_doc("192.", revision=99))  # 跳跃声明 -> rev 99
    assert build_engine(_cfg(tmp_path), persist=True).store.current_revision() == 99
    _write_rules(tmp_path, _rule_doc("203.", revision=99))  # 声明值停滞 -> rev 100
    eng = build_engine(_cfg(tmp_path), persist=True)
    assert eng.store.current_revision() == 100
    assert eng.store.rule_revisions() == [1, 2, 99, 100]
    # 再改内容，声明一个历史已用过的值 -> 仍必须单调推进而不是报错撞车
    _write_rules(tmp_path, _rule_doc("204.", revision=2))
    eng = build_engine(_cfg(tmp_path), persist=True)
    assert eng.store.current_revision() == 101


def test_empty_rules_dir_fails_startup(tmp_path):
    """rules_dir 存在但没有任何规则文件 -> 显式失败，不静默跑空规则集。"""
    (tmp_path / "rules").mkdir(parents=True)
    with pytest.raises(RuleValidationError):
        build_engine(_cfg(tmp_path), persist=True)


def test_explicit_paths_still_win_over_data_dir(tmp_path):
    """显式单独指定 journal/snapshot 位置时不被 data_dir 覆盖。"""
    d = tmp_path / "data"
    custom = tmp_path / "custom"
    cfg = Config(data_dir=d, journal_path=custom / "j.jsonl",
                 snapshot_path=custom / "s.json")
    assert cfg.journal_path == custom / "j.jsonl"
    assert cfg.snapshot_path == custom / "s.json"


def test_app_startup_fails_explicitly_with_broken_rules(tmp_path):
    """相同启动路径（create_app persist=True）下坏规则必须显式启动失败，
    而不是静默用空/旧规则把服务跑起来。"""
    from fastapi.testclient import TestClient

    from detector.api import create_app

    (tmp_path / "rules").mkdir(parents=True)
    (tmp_path / "rules" / "r.json").write_text("{broken", encoding="utf-8")
    cfg = _cfg(tmp_path)
    with (
        pytest.raises(RuleValidationError),
        TestClient(create_app(cfg, persist=True)),
    ):
        pass  # 进入 startup 即应抛出


def log_alert_revisions(alerts) -> None:
    log.info("告警版本绑定: %s",
             [(a.alert_id, a.rule_id, a.rule_revision) for a in alerts])
