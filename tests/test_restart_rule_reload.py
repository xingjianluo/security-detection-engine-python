"""重启时规则配置的加载与版本语义、非法配置失败边界，以及数据目录隔离。

覆盖：
- 磁盘规则内容变化后，以相同方式重启自动发布新版本并立刻参与判定；
- 规则内容不变（即使文件内 revision 号变化）重启保持同一版本，不多发；
- 历史告警继续绑定命中时的规则版本，不被后来改动改写；
- 规则配置非法/写坏/只写一半时，启动阶段显式失败，旧状态完好，
  不会沿用旧规则继续跑，也不会只加载一半；
- 仅改 data_dir（不显式指定 journal/snapshot/archive 位置）时，
  不同实例的本地持久化完全隔离，重启后各自回到同一份状态。
"""

import json
import logging
from pathlib import Path

import pytest

from detector.config import Config
from detector.engine import build_engine
from detector.errors import RuleValidationError
from detector.models import utcnow

from .helpers import event_payload, log_judgement

log = logging.getLogger("detector.tests")


# ---------------------------------------------------------------------- #
# 辅助
# ---------------------------------------------------------------------- #
def _cfg(tmp_path: Path, data: str = "data") -> Config:
    d = tmp_path / data
    return Config(
        rules_dir=tmp_path / "rules", data_dir=d,
        # 故意不显式给 journal_path/snapshot_path/archive_dir：
        # 它们必须跟随 data_dir
        future_tolerance_s=3600, snapshot_every=0)


def _write_rules(rules_dir: Path, doc: dict, name: str = "r1.json") -> None:
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / name).write_text(json.dumps(doc))


def _brute(severity="high", rule_id="brute"):
    return {"format_version": 2, "revision": 1, "rules": [
        {"id": rule_id, "event_type": "login", "severity": severity,
         "conditions": {"all": [
             {"field": "src_ip", "op": "prefix", "value": "10."}]}
         }]}


def _ingest(engine, eid, **kw):
    payload = event_payload(eid, timestamp=utcnow().isoformat(), **kw)
    result = engine.ingest_batch([payload], source="generic_json")
    log_judgement(payload, result)
    return result


# ---------------------------------------------------------------------- #
# 1) 规则改动后相同方式重启自动生效；内容不变版本不变
# ---------------------------------------------------------------------- #
def test_restart_publishes_new_revision_when_rules_change(tmp_path):
    cfg = _cfg(tmp_path)
    _write_rules(cfg.rules_dir, _brute("high"))

    # 首次启动：按同样启动方式自动加载规则（rev 1），命中并开告警
    eng = build_engine(cfg, persist=True)
    assert eng.store.current_revision() == 1
    _ingest(eng, "e1", severity="high")
    old = next(a for a in eng.list_alerts() if a.last_event_id == "e1")
    assert old.rule_id == "brute" and old.rule_revision == 1

    # 内容未变重启：revision 保持 1，不多发版本
    eng = build_engine(cfg, persist=True)
    assert eng.store.current_revision() == 1
    journal_before = len(eng.journal())

    # 文件里 revision 号随意改成 99，但规则内容没变 -> 仍然不发新版本
    _write_rules(cfg.rules_dir, _brute("high"))
    doc = json.loads((cfg.rules_dir / "r1.json").read_text())
    doc["revision"] = 99
    _write_rules(cfg.rules_dir, doc)
    eng = build_engine(cfg, persist=True)
    assert eng.store.current_revision() == 1
    assert len(eng.journal()) == journal_before  # 没有新增 rules_published 行

    # 改规则内容：新规则 critical_only（不同 id，避免与旧活动告警去重折叠）
    _write_rules(cfg.rules_dir, _brute("critical", rule_id="critical_only"))
    eng = build_engine(cfg, persist=True)
    assert eng.store.current_revision() == 2

    # 新版本立刻参与判定：high 事件不再命中
    _ingest(eng, "e2", severity="high")
    assert all(a.last_event_id != "e2" for a in eng.list_alerts())
    # critical 事件命中新版本规则、产生绑定 rev2 的新告警
    _ingest(eng, "e3", severity="critical")
    new = next(a for a in eng.list_alerts() if a.last_event_id == "e3")
    assert new.rule_id == "critical_only" and new.rule_revision == 2

    # 历史告警继续绑定命中时的 rev1，不被改写
    again_old = eng.get_alert(old.alert_id)
    assert again_old.rule_id == "brute"
    assert again_old.rule_revision == 1
    assert eng.store.rules_at(1) is not None
    assert eng.store.rules_at(2) is not None

    # 再以相同方式重启（当前磁盘内容 == rev2 内容）：版本不再增长
    eng = build_engine(cfg, persist=True)
    assert eng.store.current_revision() == 2
    log.info("规则重启版本语义通过: rev1 内容不变保持, 改后 rev2 生效, 历史绑定不变")


def test_restart_without_eviction_does_not_falsely_archive(tmp_path):
    """回归：没有发生淘汰时，重启（尤其规则行位于流水开头）不得把开头的
    rules_published 误当“已淘汰孤儿前缀”补归档，否则该 seq 会同时存在于
    归档与 live 流水，include_archive 完整重放报 seq 重叠。"""
    import time

    from detector.engine import replay

    cfg = _cfg(tmp_path)
    _write_rules(cfg.rules_dir, _brute("high"))
    eng = build_engine(cfg, persist=True)
    _ingest(eng, "e1", severity="high")

    # 规则变更重启（旧逻辑在这个点误把 seq1 规则行补归档）
    _write_rules(cfg.rules_dir, _brute("critical", rule_id="critical_only"))
    eng = build_engine(cfg, persist=True)
    assert eng.store.current_revision() == 2

    # 后台线程若被错误派活会很快落盘；等一下确认没有任何分段
    time.sleep(0.5)
    segs = (list(cfg.archive_dir.glob("seg-*.jsonl"))
            if cfg.archive_dir.exists() else [])
    assert segs == []
    assert eng._archive.committed_watermark() == 0

    # 完整重放不报 seq 重叠且逐条一致
    _eng2, report = replay(cfg.journal_path, cfg, include_archive=True)
    assert all(item.get("consistent") for item in report)
    revs = [i["revision"] for i in report if i["kind"] == "rules_published"]
    assert revs == [1, 2]


def test_change_in_one_of_multiple_rule_files_publishes(tmp_path):
    """目录下多个规则文件：只改其中一个文件的内容，也要发布新版本。"""
    cfg = _cfg(tmp_path)
    rdir = cfg.rules_dir
    rdir.mkdir(parents=True)
    (rdir / "a.json").write_text(json.dumps(
        {"format_version": 2, "rules": [
            {"id": "rule_a", "event_type": "login", "severity": "high",
             "conditions": {"all": [
                 {"field": "src_ip", "op": "prefix", "value": "10."}]}
             }]}))
    (rdir / "b.json").write_text(json.dumps(
        {"format_version": 2, "rules": [
            {"id": "rule_b", "event_type": "login", "severity": "low",
             "conditions": {"all": [
                 {"field": "src_ip", "op": "prefix", "value": "192.168."}]}
             }]}))

    eng = build_engine(cfg, persist=True)
    assert eng.store.current_revision() == 1
    assert {r.rule_id for r in eng.store.active_rules()} == {"rule_a", "rule_b"}

    # 内容不变重启
    assert build_engine(cfg, persist=True).store.current_revision() == 1

    # 只改 b.json（severity low -> medium），a.json 不动
    (rdir / "b.json").write_text(json.dumps(
        {"format_version": 2, "rules": [
            {"id": "rule_b", "event_type": "login", "severity": "medium",
             "conditions": {"all": [
                 {"field": "src_ip", "op": "prefix", "value": "192.168."}]}
             }]}))
    eng = build_engine(cfg, persist=True)
    assert eng.store.current_revision() == 2
    active = {r.rule_id: r for r in eng.store.active_rules()}
    assert set(active) == {"rule_a", "rule_b"}
    assert active["rule_b"].severity.value == "medium"
    # 旧版本完整保留（两条规则都在）
    rev1 = {r.rule_id: r for r in eng.store.rules_at(1)}
    assert rev1["rule_b"].severity.value == "low"


def test_restart_rule_change_visible_over_full_replay(tmp_path):
    """规则变更跨重启后，流水完整重放仍逐条一致（新版本行内嵌完整规则）。"""
    from detector.engine import replay

    cfg = _cfg(tmp_path)
    _write_rules(cfg.rules_dir, _brute("high"))
    eng = build_engine(cfg, persist=True)
    _ingest(eng, "e1", severity="high")

    _write_rules(cfg.rules_dir, _brute("critical", rule_id="critical_only"))
    eng = build_engine(cfg, persist=True)
    _ingest(eng, "e2", severity="critical")

    _eng, report = replay(cfg.journal_path, cfg, include_archive=True)
    assert all(i.get("consistent") for i in report)
    revs = sorted(i["revision"] for i in report if i["kind"] == "rules_published")
    assert revs == [1, 2]


# ---------------------------------------------------------------------- #
# 2) 非法/半写规则：启动显式失败，旧状态不被破坏
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize("bad_content", [
    '{"format_version": 2, "rules": [',                # 写了一半：截断的坏 JSON
    json.dumps({"format_version": 99, "rules": [       # 不支持的版本
        {"id": "x", "event_type": "t"}]}),
    json.dumps({"format_version": 2, "rules": [        # 未知字段
        {"id": "x", "event_type": "t", "ai_score": 0.5}]}),
    json.dumps({"format_version": 2, "rules": [        # 未知操作符
        {"id": "x", "event_type": "t",
         "conditions": {"all": [
             {"field": "src_ip", "op": "near", "value": "x"}]}}]}),
    json.dumps({"format_version": 2, "rules": []}),    # 空规则集（半套）
])
def test_invalid_rules_fail_startup_and_keep_state(tmp_path, bad_content):
    cfg = _cfg(tmp_path)
    _write_rules(cfg.rules_dir, _brute("high"))
    eng = build_engine(cfg, persist=True)
    assert eng.store.current_revision() == 1
    _ingest(eng, "e1", severity="high")
    eng.save_snapshot()
    snapshot_bytes = cfg.snapshot_path.read_bytes()
    journal_bytes = cfg.journal_path.read_bytes()

    # 把规则目录写坏
    (cfg.rules_dir / "r1.json").write_text(bad_content)

    # 启动阶段必须显式报错（不能悄悄沿用旧规则跑，也不能加载半套）
    with pytest.raises(RuleValidationError):
        build_engine(cfg, persist=True)

    # 旧状态文件原封不动
    assert cfg.snapshot_path.read_bytes() == snapshot_bytes
    assert cfg.journal_path.read_bytes() == journal_bytes

    # 修好后以同样方式重启：恢复到旧的可用状态（rev1 + e1），不补发半套版本
    _write_rules(cfg.rules_dir, _brute("high"))
    eng = build_engine(cfg, persist=True)
    assert eng.store.current_revision() == 1
    assert eng.stats()["events"] == 1
    assert eng.get_event("e1") is not None
    # 重复投递仍判重：幂等锚点随旧状态完好恢复
    r = _ingest(eng, "e1", severity="high")
    assert r.accepted[0].dedup_hit is True
    # 规则版本仍然是 1（坏配置期间没有留下任何新版本）
    assert eng.store.current_revision() == 1


def test_one_bad_file_in_dir_aborts_entire_load(tmp_path):
    """目录下多文件，一个写坏 -> 整套拒绝，另一个好文件也不生效（无半套）。"""
    cfg = _cfg(tmp_path)
    rdir = cfg.rules_dir
    rdir.mkdir(parents=True)
    (rdir / "a-good.json").write_text(json.dumps(
        {"format_version": 2, "rules": [
            {"id": "good_rule", "event_type": "login", "severity": "low"}]}))
    (rdir / "b-bad.json").write_text('{"format_version": 2, "rules": [ {"oops"')

    with pytest.raises(RuleValidationError):
        build_engine(cfg, persist=True)

    # 引擎从未对外可用；磁盘上不产生任何快照/流水
    assert not cfg.snapshot_path.exists()
    assert not cfg.journal_path.exists()


# ---------------------------------------------------------------------- #
# 3) data_dir 跟随：不同实例互不串持久化数据
# ---------------------------------------------------------------------- #
def test_data_dir_isolates_persistence(tmp_path):
    cfg_a = _cfg(tmp_path, "dataA")
    cfg_b = _cfg(tmp_path, "dataB")
    # 关键断言：未显式指定路径时，全部持久化位置跟随各自 data_dir
    assert cfg_a.journal_path == tmp_path / "dataA" / "journal.jsonl"
    assert cfg_a.snapshot_path == tmp_path / "dataA" / "snapshot.json"
    assert cfg_a.archive_dir == tmp_path / "dataA" / "archive"
    assert cfg_b.journal_path == tmp_path / "dataB" / "journal.jsonl"
    assert cfg_b.archive_dir == tmp_path / "dataB" / "archive"

    _write_rules(cfg_a.rules_dir, _brute("high"))

    eng_a = build_engine(cfg_a, persist=True)
    _ingest(eng_a, "a-only", severity="high")
    assert eng_a.stats()["events"] == 1
    eng_a.save_snapshot()

    # 实例 B 指向不同 data_dir：读不到 A 的任何记录
    eng_b = build_engine(cfg_b, persist=True)
    assert eng_b.stats()["events"] == 0
    assert eng_b.get_event("a-only") is None
    assert eng_b.list_alerts() == []
    _ingest(eng_b, "b-only", severity="high")
    assert eng_b.stats()["events"] == 1

    # A 重启后回到自己的状态，看不到 B 的数据
    eng_a2 = build_engine(cfg_a, persist=True)
    assert eng_a2.stats()["events"] == 1
    assert eng_a2.get_event("a-only") is not None
    assert eng_a2.get_event("b-only") is None

    # B 重启后回到 B 自己的状态
    eng_b2 = build_engine(cfg_b, persist=True)
    assert eng_b2.stats()["events"] == 1
    assert eng_b2.get_event("b-only") is not None
    assert eng_b2.get_event("a-only") is None

    # 物理文件确实落在各自目录
    assert (tmp_path / "dataA" / "journal.jsonl").exists()
    assert (tmp_path / "dataB" / "journal.jsonl").exists()
    assert (tmp_path / "dataA" / "snapshot.json").exists()
    assert (tmp_path / "dataB" / "snapshot.json").exists()
    log.info("数据目录隔离通过: A/B 各自独立持久化与重启接续")


def test_explicit_paths_override_data_dir(tmp_path):
    """显式指定 journal/snapshot 位置时以显式位置为准（向后兼容）。"""
    shared = tmp_path / "shared"
    cfg = Config(
        rules_dir=tmp_path / "rules", data_dir=tmp_path / "data",
        journal_path=shared / "j.jsonl", snapshot_path=shared / "s.json",
        archive_dir=shared / "arc", future_tolerance_s=3600)
    assert cfg.journal_path == shared / "j.jsonl"
    assert cfg.snapshot_path == shared / "s.json"
    assert cfg.archive_dir == shared / "arc"


def test_default_data_dir_paths_preserved():
    """不带 data_dir 的默认构造仍解析到 data/ 下（原默认位置不变）。"""
    cfg = Config()
    assert cfg.journal_path == Path("data/journal.jsonl")
    assert cfg.snapshot_path == Path("data/snapshot.json")
    assert cfg.archive_dir == Path("data/archive")
