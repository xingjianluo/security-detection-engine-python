"""本地检测规则的加载、版本兼容与匹配。

规则文档格式
============
顶层::

    {"format_version": 1|2, "revision": <int 可选>, "rules": [ ... ]}

v1 规则（扁平阈值语义，旧格式在新版本下按原语义生效）::

    {"id": "r1", "name": "...", "event_type": "ssh_failed_login",
     "min_severity": "medium", "window_seconds": 300}

v2 规则（结构化条件 + 关联/抑制/合并）::

    {"id": "r2", "version": 2, "name": "...", "event_type": "t",
     "severity": "high",
     "conditions": {"all": [
         {"field": "src_ip", "op": "eq", "value": "1.2.3.4"},
         {"field": "severity", "op": "gte", "value": "medium"}]},
     "dedup_window_s": 300,
     "correlation_key": ["src_ip", "user"],
     "merge_key": ["rule_id", "src_ip"],
     "suppress": {"window_s": 600, "max_severity": "medium"}}

兼容性原则：出现任何未声明的字段/操作符/版本号都显式拒绝，
绝不静默忽略（UnsupportedRule*Error）。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import (
    RuleValidationError,
    UnsupportedRuleFieldError,
    UnsupportedRuleSemanticsError,
    UnsupportedRuleVersionError,
)
from .models import Event, MatchTrace, Rule, Severity

# 各版本规则允许的顶层字段（白名单：多余字段即拒绝）
_V1_FIELDS = frozenset({"id", "name", "event_type", "min_severity",
                        "window_seconds", "enabled"})
_V2_FIELDS = frozenset({
    "id", "version", "name", "event_type", "severity", "conditions",
    "dedup_window_s", "suppress_window_s", "suppress_max_severity",
    "correlation_key", "merge_key", "enabled",
    # 旧式嵌套抑制写法（v2 早期草稿），归一到同一内部语义
    "suppress",
})
_DOC_FIELDS = frozenset({"format_version", "revision", "rules"})
_CONDITION_FIELDS = frozenset({"field", "op", "value"})
_COMBINATORS = frozenset({"all", "any", "not"})

# 条件可访问的事件字段（归一模型）
_EVENT_FIELDS = frozenset({
    "event_id", "event_type", "severity", "src_ip", "dst_ip",
    "user", "host", "action",
})

_OPS = frozenset({"eq", "ne", "in", "prefix", "regex", "gte", "lte"})


def _sev(raw: Any, where: str) -> Severity:
    if not isinstance(raw, str) or raw not in {s.value for s in Severity}:
        raise RuleValidationError(f"{where}: invalid severity {raw!r}")
    return Severity(raw)


def _check_whitelist(raw: dict[str, Any], allowed: frozenset[str], where: str) -> None:
    unknown = set(raw) - allowed
    if unknown:
        raise UnsupportedRuleFieldError(
            f"{where}: unsupported field(s) {sorted(unknown)} "
            f"(allowed={sorted(allowed)})",
            reason="unsupported_rule_field",
        )


def _window(raw: dict[str, Any], *names: str, default: int, where: str) -> int:
    for name in names:
        if name in raw:
            value = raw[name]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise RuleValidationError(
                    f"{where}: {name!r} must be a non-negative integer"
                )
            return value
    return default


def normalize_rule_v1(raw: dict[str, Any], revision: int) -> Rule:
    if not isinstance(raw, dict):
        raise RuleValidationError("v1 rule entry must be an object")
    _check_whitelist(raw, _V1_FIELDS, "v1 rule")
    if "id" not in raw:
        raise RuleValidationError("v1 rule missing 'id'")
    if "event_type" not in raw:
        raise RuleValidationError(f"v1 rule {raw.get('id')!r} missing 'event_type'")
    conditions: dict[str, Any] = {}
    if "min_severity" in raw:
        _sev(raw["min_severity"], f"v1 rule {raw['id']!r}.min_severity")
        conditions = {"all": [{"field": "severity", "op": "gte",
                               "value": raw["min_severity"]}]}
    return Rule(
        rule_id=str(raw["id"]),
        version=1,
        revision=revision,
        name=str(raw.get("name", raw["id"])),
        event_type=str(raw["event_type"]),
        conditions=conditions,
        severity=_sev(raw.get("min_severity", "info"),
                      f"v1 rule {raw['id']!r}.min_severity"),
        dedup_window_s=_window(raw, "window_seconds", default=300,
                               where=f"v1 rule {raw['id']!r}"),
        enabled=bool(raw.get("enabled", True)),
    )


def _validate_condition(node: Any, where: str) -> None:
    if not isinstance(node, dict):
        raise RuleValidationError(f"{where}: condition node must be an object")
    combinators = set(node) & _COMBINATORS
    leaves = set(node) & {"field"}
    if combinators and leaves:
        raise UnsupportedRuleSemanticsError(
            f"{where}: cannot mix combinator and leaf in one node",
            reason="unsupported_rule_semantics",
        )
    if combinators:
        if len(combinators) > 1:
            raise UnsupportedRuleSemanticsError(
                f"{where}: only one combinator per node",
                reason="unsupported_rule_semantics",
            )
        comb = next(iter(combinators))
        _check_whitelist(node, _COMBINATORS, where)
        children = node[comb]
        if comb == "not":
            if not isinstance(children, dict):
                raise RuleValidationError(f"{where}: 'not' requires one node")
            _validate_condition(children, f"{where}.not")
        else:
            if not isinstance(children, list) or not children:
                raise RuleValidationError(f"{where}: {comb!r} requires non-empty list")
            for i, child in enumerate(children):
                _validate_condition(child, f"{where}.{comb}[{i}]")
        return
    if leaves:
        _check_whitelist(node, _CONDITION_FIELDS, where)
        missing = _CONDITION_FIELDS - set(node)
        if missing:
            raise RuleValidationError(f"{where}: leaf missing {sorted(missing)}")
        if node["field"] not in _EVENT_FIELDS:
            raise UnsupportedRuleFieldError(
                f"{where}: unknown event field {node['field']!r}",
                reason="unsupported_rule_field",
            )
        if node["op"] not in _OPS:
            raise UnsupportedRuleSemanticsError(
                f"{where}: unsupported operator {node['op']!r}",
                reason="unsupported_rule_semantics",
            )
        if node["op"] == "in" and not isinstance(node["value"], list):
            raise RuleValidationError(f"{where}: op 'in' requires list value")
        if node["field"] == "severity":
            _sev(node["value"], where)
        return
    raise UnsupportedRuleSemanticsError(
        f"{where}: empty condition node (no combinator or field)",
        reason="unsupported_rule_semantics",
    )


def normalize_rule_v2(raw: dict[str, Any], revision: int) -> Rule:
    if not isinstance(raw, dict):
        raise RuleValidationError("v2 rule entry must be an object")
    _check_whitelist(raw, _V2_FIELDS, "v2 rule")
    declared_ver = raw.get("version", 2)
    if declared_ver != 2:
        raise UnsupportedRuleVersionError(
            f"rule {raw.get('id')!r} declares version {declared_ver} in a v2 document"
        )
    if "id" not in raw:
        raise RuleValidationError("v2 rule missing 'id'")
    if "event_type" not in raw:
        raise RuleValidationError(f"v2 rule {raw['id']!r} missing 'event_type'")
    rid = str(raw["id"])
    conditions = raw.get("conditions", {})
    _validate_condition(conditions, f"v2 rule {rid!r}.conditions")

    supp_window = 0
    supp_max: Severity | None = None
    if "suppress" in raw:
        supp = raw["suppress"]
        if not isinstance(supp, dict):
            raise RuleValidationError(f"v2 rule {rid!r}: 'suppress' must be object")
        unknown = set(supp) - {"window_s", "max_severity"}
        if unknown:
            raise UnsupportedRuleFieldError(
                f"v2 rule {rid!r}.suppress: unsupported {sorted(unknown)}"
            )
        supp_window = _window(supp, "window_s", default=0,
                              where=f"v2 rule {rid!r}.suppress")
        if "max_severity" in supp:
            supp_max = _sev(supp["max_severity"], f"v2 rule {rid!r}.suppress.max_severity")
    supp_window = _window(raw, "suppress_window_s", default=supp_window,
                          where=f"v2 rule {rid!r}")
    if "suppress_max_severity" in raw:
        supp_max = _sev(raw["suppress_max_severity"],
                        f"v2 rule {rid!r}.suppress_max_severity")

    corr = raw.get("correlation_key", [])
    merge = raw.get("merge_key", ["rule_id"])
    for name, keys in (("correlation_key", corr), ("merge_key", merge)):
        if not isinstance(keys, list) or any(not isinstance(k, str) for k in keys):
            raise RuleValidationError(f"v2 rule {rid!r}.{name} must be list[str]")
        bad = [k for k in keys if k not in _EVENT_FIELDS and k != "rule_id"]
        if bad:
            raise UnsupportedRuleFieldError(
                f"v2 rule {rid!r}.{name}: unknown field(s) {bad}"
            )

    return Rule(
        rule_id=rid,
        version=2,
        revision=revision,
        name=str(raw.get("name", rid)),
        event_type=str(raw["event_type"]),
        conditions=conditions,
        severity=_sev(raw.get("severity", "medium"), f"v2 rule {rid!r}.severity"),
        dedup_window_s=_window(raw, "dedup_window_s", default=300,
                               where=f"v2 rule {rid!r}"),
        suppress_window_s=supp_window,
        suppress_max_severity=supp_max,
        correlation_key=corr,
        merge_key=merge,
        enabled=bool(raw.get("enabled", True)),
    )


def load_rule_document(raw: dict[str, Any]) -> tuple[list[Rule], int]:
    """解析一份规则文档，返回 (规则列表, 文档声明的 revision 或 0)。"""
    if not isinstance(raw, dict):
        raise RuleValidationError("rule document must be a JSON object")
    _check_whitelist(raw, _DOC_FIELDS, "rule document")
    version = raw.get("format_version")
    if version not in (1, 2):
        raise UnsupportedRuleVersionError(
            f"unsupported format_version={version!r}; supported: [1, 2]",
            reason="unsupported_rule_version",
        )
    entries = raw.get("rules")
    if not isinstance(entries, list) or not entries:
        raise RuleValidationError("rule document requires non-empty 'rules' list")
    revision = raw.get("revision", 0)
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise RuleValidationError("'revision' must be a non-negative integer")

    seen_ids: set[str] = set()
    rules: list[Rule] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuleValidationError("rule entry must be an object")
        # v2 文档允许内嵌旧版 v1 条目（version==1），按原语义加载
        entry_version = entry.get("version", version)
        if entry_version not in (1, 2):
            raise UnsupportedRuleVersionError(
                f"rule {entry.get('id')!r}: unsupported version {entry_version!r}"
            )
        rule = (
            normalize_rule_v1(entry, revision)
            if entry_version == 1
            else normalize_rule_v2(entry, revision)
        )
        if rule.rule_id in seen_ids:
            raise RuleValidationError(f"duplicate rule id in document: {rule.rule_id!r}")
        seen_ids.add(rule.rule_id)
        rules.append(rule)
    return rules, revision


def load_rules_dir(path: Path) -> tuple[list[Rule], int]:
    """从目录加载所有 ``.json`` 规则文件，合并为一个规则集。

    多个文件各自可声明 revision；取最大值作为规则集文档版本号，
    规则内部 ``revision`` 统一盖戳为该值（同一发布批次）。

    本函数为纯读取/校验：目录下任一文件非法（坏 JSON、未知字段、
    语义错误等）都会在触碰任何引擎状态之前抛出，调用方不会得到
    “只加载了一半”的规则集。
    """
    files = sorted(Path(path).glob("*.json"))
    if not files:
        raise RuleValidationError(f"no *.json rule files under {path}")
    all_rules: list[Rule] = []
    revision = 0
    for file in files:
        try:
            raw = json.loads(file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuleValidationError(f"{file}: invalid JSON ({exc})") from exc
        rules, doc_rev = load_rule_document(raw)
        revision = max(revision, doc_rev)
        all_rules.extend(rules)
    ids = [r.rule_id for r in all_rules]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise RuleValidationError(f"duplicate rule id across files: {dupes}")
    stamped = [
        Rule(**{**r.__dict__, "revision": revision}) if r.revision != revision else r
        for r in all_rules
    ]
    return stamped, revision


def rules_bundle_digest(rules: list[Rule]) -> str:
    """规则集“内容摘要”：只取决于规则内容本身，与盖戳 revision 无关。

    重启时据此判断磁盘上的规则配置相对当前生效版本是否真的变化：
    内容不变（包括仅文件中的 revision 号变化）摘要相同 -> 不发新版本；
    任一条规则增删改 -> 摘要变化 -> 发布新版本。
    """
    canonical = [
        rule_to_dict(Rule(**{**r.__dict__, "revision": 0}))
        for r in sorted(rules, key=lambda r: r.rule_id)
    ]
    from .models import input_digest

    return input_digest(canonical)


# ---- 评估 ---------------------------------------------------------------

def _field_value(event: Event, name: str) -> Any:
    if name == "severity":
        return event.severity
    return getattr(event, name, None)


def _leaf_ok(leaf: dict[str, Any], event: Event, checks: list[str]) -> bool:
    name, op, expected = leaf["field"], leaf["op"], leaf["value"]
    actual = _field_value(event, name)
    if name == "severity":
        actual_rank = actual.rank if isinstance(actual, Severity) else -1
        expected_rank = Severity(expected).rank
        if op == "gte":
            ok = actual_rank >= expected_rank
        elif op == "lte":
            ok = actual_rank <= expected_rank
        elif op == "eq":
            ok = actual_rank == expected_rank
        else:
            raise UnsupportedRuleSemanticsError(
                f"severity supports only eq/gte/lte, got {op!r}"
            )
        checks.append(f"{name}({getattr(actual, 'value', None)}) {op} {expected} -> {ok}")
        return ok

    import re

    if op == "eq":
        ok = actual == expected
    elif op == "ne":
        ok = actual != expected
    elif op == "in":
        ok = actual in expected
    elif op == "prefix":
        ok = isinstance(actual, str) and actual.startswith(expected)
    elif op == "regex":
        ok = isinstance(actual, str) and re.search(expected, actual) is not None
    else:  # gte/lte on non-severity 字段（数值/字符串比较）
        try:
            ok = actual >= expected if op == "gte" else actual <= expected
        except TypeError:
            ok = False
    checks.append(f"{name}({actual!r}) {op} {expected!r} -> {ok}")
    return ok


def _node_ok(node: dict[str, Any], event: Event, checks: list[str]) -> bool:
    if "all" in node:
        results = [_node_ok(c, event, checks) for c in node["all"]]
        ok = all(results)
        checks.append(f"all{results} -> {ok}")
        return ok
    if "any" in node:
        results = [_node_ok(c, event, checks) for c in node["any"]]
        ok = any(results)
        checks.append(f"any{results} -> {ok}")
        return ok
    if "not" in node:
        inner = _node_ok(node["not"], event, checks)
        ok = not inner
        checks.append(f"not({inner}) -> {ok}")
        return ok
    return _leaf_ok(node, event, checks)


def evaluate(rule: Rule, event: Event) -> MatchTrace:
    """对单条规则评估单条事件，产出判定依据。

    规则的 ``severity`` 是基线门槛：事件严重度低于它则规则不命中
    （v1 由 min_severity 转换而来，语义一致）。
    """
    checks: list[str] = []
    type_ok = event.event_type == rule.event_type
    checks.append(f"event_type({event.event_type}) == {rule.event_type} -> {type_ok}")
    sev_ok = event.severity.rank >= rule.severity.rank
    checks.append(
        f"severity({event.severity.value}) >= {rule.severity.value} -> {sev_ok}"
    )
    cond_ok = _node_ok(rule.conditions, event, checks) if rule.conditions else True
    matched = type_ok and sev_ok and cond_ok and rule.enabled
    checks.append(f"enabled={rule.enabled} => matched={matched}")
    return MatchTrace(
        matched=matched,
        rule_id=rule.rule_id,
        rule_version=rule.version,
        rule_revision=rule.revision,
        checks=checks,
    )


def match_any(rules: list[Rule], event: Event) -> tuple[Rule | None, MatchTrace]:
    """按规则在规则集中的顺序返回首个命中；未命中返回最后的评估轨迹。"""
    last_trace = MatchTrace(False, "", 0, 0, ["no rules"])
    for rule in rules:
        trace = evaluate(rule, event)
        if trace.matched:
            return rule, trace
        last_trace = trace
    return None, last_trace


# ---------------------------------------------------------------------- #
# 规则的自包含序列化（用于流水/归档，使重放不依赖 rules 目录原文）
# ---------------------------------------------------------------------- #

def rule_to_dict(rule: Rule) -> dict:
    return {
        "rule_id": rule.rule_id,
        "version": rule.version,
        "revision": rule.revision,
        "name": rule.name,
        "event_type": rule.event_type,
        "conditions": rule.conditions,
        "severity": rule.severity.value,
        "dedup_window_s": rule.dedup_window_s,
        "suppress_window_s": rule.suppress_window_s,
        "suppress_max_severity": (
            rule.suppress_max_severity.value
            if rule.suppress_max_severity else None),
        "correlation_key": rule.correlation_key,
        "merge_key": rule.merge_key,
        "enabled": rule.enabled,
    }


def rule_from_dict(raw: dict, *, revision: int | None = None) -> Rule:
    return Rule(
        rule_id=raw["rule_id"],
        version=int(raw["version"]),
        revision=int(raw["revision"] if revision is None else revision),
        name=raw["name"],
        event_type=raw["event_type"],
        conditions=raw["conditions"],
        severity=Severity(raw["severity"]),
        dedup_window_s=raw["dedup_window_s"],
        suppress_window_s=raw.get("suppress_window_s", 0),
        suppress_max_severity=(
            Severity(raw["suppress_max_severity"])
            if raw.get("suppress_max_severity") else None),
        correlation_key=raw.get("correlation_key", []),
        merge_key=raw.get("merge_key", []),
        enabled=raw.get("enabled", True),
    )
