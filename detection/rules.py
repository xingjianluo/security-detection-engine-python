"""Local rule file loading with explicit version semantics.

Rule document (JSON object)
---------------------------
``id``          (required, non-empty string)
``version``     (required, ``"v1"`` or ``"v2"``)
``revision``    (optional, positive integer; default 1)
``name``        (required, non-empty string)
``condition``   (required, ``{"field", "op", "value"}``)
``severity``    (required, ``low|medium|high|critical`` or 0..10)
``dedupe_window_seconds``    (v2 only, optional, positive int)
``suppress_key``             (v2 only, optional, non-empty string)
``suppress_severity_ceiling`` (v2 only, optional, severity)

Compatibility contract
-----------------------
- v1 documents keep their original semantics forever: only ``eq/neq/contains``
  operators are valid and v2-only fields must be absent.
- Unknown top-level fields, unknown operators and unsupported value types are
  *rejected* (never silently ignored) with a distinct reason code.
- A reload is atomic: either every rule in the file loads, or none changes.
"""

from __future__ import annotations

import hashlib
import json

from detection.config import EngineConfig
from detection.errors import (
    RuleRejectedError,
    RejectReason,
)
from detection.models import (
    ConditionOp,
    Rule,
    RuleCondition,
    RuleFormatVersion,
    Severity,
)
from detection.store import RuleStore

_V1_OPS = {ConditionOp.EQ, ConditionOp.NEQ, ConditionOp.CONTAINS}
_V2_OPS = set(ConditionOp)

_ALLOWED_TOP_LEVEL = {
    "id", "version", "revision", "name", "condition", "severity",
    "dedupe_window_seconds", "suppress_key", "suppress_severity_ceiling",
}
_ALLOWED_CONDITION_FIELDS = {"field", "op", "value"}


def _reject(reason: RejectReason, message: str) -> None:
    raise RuleRejectedError(reason, message)


def rule_signature(raw: dict) -> str:
    """Stable semantic digest of a rule document."""
    blob = json.dumps(raw, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def _parse_condition(raw: object, version: RuleFormatVersion) -> RuleCondition:
    if not isinstance(raw, dict):
        _reject(RejectReason.RULE_MISSING_FIELD, "condition must be an object")
    unknown = set(raw) - _ALLOWED_CONDITION_FIELDS
    if unknown:
        _reject(
            RejectReason.RULE_FIELD_UNSUPPORTED,
            f"unknown condition fields: {sorted(unknown)}",
        )
    for name in ("field", "op", "value"):
        if name not in raw:
            _reject(RejectReason.RULE_MISSING_FIELD, f"condition.{name} is required")
    field = raw["field"]
    op_raw = raw["op"]
    if not isinstance(field, str) or not field:
        _reject(RejectReason.RULE_MISSING_FIELD, "condition.field must be a non-empty string")
    try:
        op = ConditionOp(op_raw)
    except ValueError:
        _reject(RejectReason.RULE_SEMANTIC_UNSUPPORTED, f"unknown operator: {op_raw!r}")
    allowed_ops = _V1_OPS if version == RuleFormatVersion.V1 else _V2_OPS
    if op not in allowed_ops:
        _reject(
            RejectReason.RULE_SEMANTIC_UNSUPPORTED,
            f"operator {op.value!r} is not supported by {version.value} rules",
        )
    value = raw["value"]
    if op == ConditionOp.CONTAINS and not isinstance(value, str):
        _reject(RejectReason.RULE_SEMANTIC_UNSUPPORTED,
                "operator 'contains' requires a string value")
    if op in (ConditionOp.GT, ConditionOp.GTE, ConditionOp.LT, ConditionOp.LTE):
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            _reject(RejectReason.RULE_SEMANTIC_UNSUPPORTED,
                    f"operator {op.value!r} requires a numeric value")
    if op == ConditionOp.REGEX:
        import re
        if not isinstance(value, str):
            _reject(RejectReason.RULE_SEMANTIC_UNSUPPORTED,
                    "operator 'regex' requires a string value")
        try:
            re.compile(value)
        except re.error as exc:
            _reject(RejectReason.RULE_SEMANTIC_UNSUPPORTED,
                    f"invalid regex: {exc}")
    return RuleCondition(field=field, op=op, value=value)


def parse_rule(raw: object, *, assumed_version: RuleFormatVersion | None = None) -> Rule:
    if not isinstance(raw, dict):
        _reject(RejectReason.RULE_MISSING_FIELD, "rule must be a JSON object")
    unknown = set(raw) - _ALLOWED_TOP_LEVEL
    if unknown:
        _reject(RejectReason.RULE_FIELD_UNSUPPORTED,
                f"unknown rule fields: {sorted(unknown)}")

    for name in ("id", "name", "version", "condition", "severity"):
        if name not in raw or raw[name] in (None, ""):
            _reject(RejectReason.RULE_MISSING_FIELD, f"rule.{name} is required")

    rule_id = raw["id"]
    name = raw["name"]
    if not isinstance(rule_id, str) or not isinstance(name, str):
        _reject(RejectReason.RULE_MISSING_FIELD, "rule.id and rule.name must be strings")

    version_raw = raw["version"]
    if assumed_version is not None:
        version_raw = assumed_version.value if version_raw is None else version_raw
    try:
        version = RuleFormatVersion(version_raw)
    except ValueError:
        _reject(RejectReason.RULE_VERSION_UNSUPPORTED,
                f"rule {rule_id}: unsupported rule format version {version_raw!r}")

    # v1 documents may not carry v2-only fields: silently accepting them would
    # change the original semantics of the rule.
    v2_only = {"dedupe_window_seconds", "suppress_key", "suppress_severity_ceiling"}
    if version == RuleFormatVersion.V1:
        present = v2_only.intersection(raw)
        if present:
            _reject(
                RejectReason.RULE_SEMANTIC_UNSUPPORTED,
                f"v1 rule {rule_id} may not declare v2-only fields: {sorted(present)}",
            )

    revision = raw.get("revision", 1)
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        _reject(RejectReason.RULE_SEMANTIC_UNSUPPORTED,
                f"rule {rule_id}: revision must be a positive integer")

    condition = _parse_condition(raw["condition"], version)
    severity = Severity.coerce(raw["severity"])
    if severity is None:
        _reject(RejectReason.RULE_SEMANTIC_UNSUPPORTED,
                f"rule {rule_id}: invalid severity {raw['severity']!r}")

    dedupe_window = None
    suppress_key = None
    suppress_ceiling = None
    if version == RuleFormatVersion.V2:
        dedupe_window = raw.get("dedupe_window_seconds")
        if dedupe_window is not None:
            if not isinstance(dedupe_window, int) or isinstance(dedupe_window, bool) or dedupe_window <= 0:
                _reject(RejectReason.RULE_SEMANTIC_UNSUPPORTED,
                        f"rule {rule_id}: dedupe_window_seconds must be a positive integer")
        suppress_key = raw.get("suppress_key")
        if suppress_key is not None and (not isinstance(suppress_key, str) or not suppress_key):
            _reject(RejectReason.RULE_SEMANTIC_UNSUPPORTED,
                    f"rule {rule_id}: suppress_key must be a non-empty string")
        if "suppress_severity_ceiling" in raw:
            suppress_ceiling = Severity.coerce(raw["suppress_severity_ceiling"])
            if suppress_ceiling is None:
                _reject(RejectReason.RULE_SEMANTIC_UNSUPPORTED,
                        f"rule {rule_id}: invalid suppress_severity_ceiling")
        if suppress_ceiling is not None and suppress_key is None:
            _reject(RejectReason.RULE_SEMANTIC_UNSUPPORTED,
                    f"rule {rule_id}: suppress_severity_ceiling requires suppress_key")

    return Rule(
        rule_id=rule_id,
        version=version,
        name=name,
        condition=condition,
        severity=severity,
        rule_revision=revision,
        dedupe_window_seconds=dedupe_window,
        suppress_key=suppress_key,
        suppress_severity_ceiling=suppress_ceiling,
        signature=rule_signature(raw),
    )


def parse_rules_document(
    doc: object,
    *,
    assumed_version: RuleFormatVersion | None = None,
) -> list[Rule]:
    """Parse a full rules file. The whole document is parsed first; callers
    commit to the store only after every rule succeeds."""
    file_version = assumed_version
    if isinstance(doc, dict) and "rules" in doc and set(doc) <= {"rules", "version"}:
        if file_version is None and "version" in doc:
            try:
                file_version = RuleFormatVersion(doc["version"])
            except ValueError:
                _reject(RejectReason.RULE_VERSION_UNSUPPORTED,
                        f"unsupported file-level rule version {doc['version']!r}")
        doc = doc["rules"]
    if not isinstance(doc, list):
        _reject(RejectReason.RULE_MISSING_FIELD,
                "rules file must be an array or {'rules': [...]}")
    parsed: list[Rule] = []
    seen: set[tuple[str, int]] = set()
    for index, raw in enumerate(doc):
        if file_version is not None and isinstance(raw, dict) and "version" not in raw:
            raw = {**raw, "version": file_version.value}
        rule = parse_rule(raw)
        key = (rule.rule_id, rule.rule_revision)
        if key in seen:
            _reject(RejectReason.RULE_DUPLICATE_ID,
                    f"duplicate rule id/revision at index {index}: {rule.rule_id}@{rule.rule_revision}")
        seen.add(key)
        parsed.append(rule)
    return parsed


def load_rules_file(
    path: str,
    store: RuleStore,
    *,
    cfg: EngineConfig,
    assumed_version: RuleFormatVersion | None = None,
) -> list[Rule]:
    """Read, parse and atomically activate the rules file."""
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        _reject(RejectReason.RULE_MISSING_FIELD, f"rules file is not valid JSON: {exc}")
    rules = parse_rules_document(doc, assumed_version=assumed_version)
    store.replace_all(rules)
    return rules
