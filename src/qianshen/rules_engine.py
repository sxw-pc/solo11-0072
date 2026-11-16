"""声明式规则加载、匹配及文件级检查。"""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import yaml
from .config import Config
from .file_checks import file_check_findings
from .models import FileInfo, Finding, Rule, StatementInfo, make_finding
from .util import (
    QianshenError, canonical_json, downgrade_severity, path_matches, sha256_text,
)
ALLOWED_MATCH = {
    "kind", "actions_any", "where", "if_not_exists", "if_exists", "not_null",
    "has_default", "type_change", "permission_not_allowed", "requires_no_backfill",
    "large_table", "sql_regex", "check",
}
CHECKS = {
    "large_table_ddl_offline", "ddl_dml_in_transaction", "long_transaction_marker",
    "duplicate_object", "fixed_key_insert", "non_idempotent_dml",
}
@dataclass
class RulesBundle:
    rules: list[Rule]
    sha256: str
    snapshots: list[dict[str, Any]]

def _list(value: Any, name: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise QianshenError(f"规则字段 {name} 必须是字符串或字符串列表")
    return list(value)

def load_rules(config: Config) -> RulesBundle:
    try:
        raw = yaml.safe_load(config.rules_file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise QianshenError(f"规则集读取失败: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("rules"), list):
        raise QianshenError("规则文件必须包含 rules 列表")
    rules: list[Rule] = []
    seen: set[str] = set()
    for item in raw["rules"]:
        if not isinstance(item, dict):
            raise QianshenError("规则条目必须是映射")
        rule_id = item.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise QianshenError("每条规则必须有非空 id")
        if rule_id in seen:
            raise QianshenError(f"规则 ID 重复: {rule_id}")
        seen.add(rule_id)
        severity = str(item.get("severity", "")).lower()
        if severity not in ("blocker", "warning", "info"):
            raise QianshenError(f"规则 {rule_id} severity 无效")
        match = item.get("match")
        if not isinstance(match, dict):
            raise QianshenError(f"规则 {rule_id} 缺少 match 映射")
        unknown = set(match) - ALLOWED_MATCH
        if unknown:
            raise QianshenError(f"规则 {rule_id} match 含未知条件: {sorted(unknown)}")
        if "check" in match and match["check"] not in CHECKS:
            raise QianshenError(f"规则 {rule_id} 使用了未知检查: {match['check']}")
        override = config.rule_overrides.get(rule_id, {})
        rule = Rule(
            id=rule_id, title=str(item.get("title", rule_id)),
            severity=override.get("severity", severity),
            category=str(item.get("category", "other")),
            applies_to=_list(item.get("applies_to", ["statement"]), "applies_to"),
            match=dict(match),
            message=str(item.get("message", item.get("title", rule_id))),
            suggestion=str(item.get("suggestion", "")),
            enabled=bool(override.get("enabled", item.get("enabled", True))),
            dialects=_list(item.get("dialects"), "dialects"),
            directions=_list(item.get("directions"), "directions"),
            path_globs=_list(item.get("path_globs"), "path_globs"),
        )
        rules.append(rule)
    unknown_overrides = set(config.rule_overrides) - seen
    if unknown_overrides:
        raise QianshenError(f"rule_overrides 含未知规则: {sorted(unknown_overrides)}")
    rules.sort(key=lambda rule: rule.id)
    snapshots = [rule.snapshot() for rule in rules]
    return RulesBundle(rules, sha256_text(canonical_json(snapshots)), snapshots)

def _render(template: str, values: dict[str, Any]) -> str:
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError):
        return template

def _scope_allows(rule: Rule, file: FileInfo, config: Config) -> bool:
    if rule.dialects and config.dialect not in rule.dialects:
        return False
    if rule.directions and file.direction not in rule.directions:
        return False
    if rule.path_globs and not any(path_matches(file.rel_path, pattern) for pattern in rule.path_globs):
        return False
    return True

def _has_backfill(statement: StatementInfo, file_statements: list[StatementInfo]) -> bool:
    table = str(statement.attrs.get("table") or "")
    return any(
        item.kind == "update" and str(item.attrs.get("table") or "") == table
        for item in file_statements
    )

def _column_criteria(stmt: StatementInfo, criteria: dict[str, Any]) -> bool:
    columns = stmt.attrs.get("added_columns") or []
    want_not_null = criteria.get("not_null")
    want_default = criteria.get("has_default")
    for column in columns:
        if want_not_null is not None and bool(column.get("not_null")) != bool(want_not_null):
            continue
        if want_default is not None and bool(column.get("has_default")) != bool(want_default):
            continue
        return True
    return False

def _match_statement(
    match: dict[str, Any], stmt: StatementInfo, file: FileInfo, config: Config,
    file_statements: list[StatementInfo],
) -> bool:
    if "kind" in match:
        kinds = _list(match["kind"], "kind")
        if stmt.kind not in kinds:
            return False
    if "actions_any" in match and not set(stmt.actions) & set(_list(match["actions_any"], "actions_any")):
        return False
    if "where" in match and bool(stmt.attrs.get("has_where")) != bool(match["where"]):
        return False
    if "if_not_exists" in match:
        value = stmt.attrs.get("has_if_not_exists", stmt.attrs.get("if_not_exists", False))
        if bool(value) != bool(match["if_not_exists"]):
            return False
    if "if_exists" in match and bool(stmt.attrs.get("if_exists", False)) != bool(match["if_exists"]):
        return False
    if "not_null" in match or "has_default" in match:
        if not _column_criteria(stmt, match):
            return False
    if "type_change" in match and stmt.attrs.get("type_change") not in _list(
        match["type_change"], "type_change"
    ):
        return False
    if "permission_not_allowed" in match:
        if bool(match["permission_not_allowed"]) and config.allow_grants:
            return False
    if "requires_no_backfill" in match and bool(match["requires_no_backfill"]):
        if _has_backfill(stmt, file_statements):
            return False
    if "large_table" in match and bool(match["large_table"]):
        table = str(stmt.attrs.get("table") or (stmt.objects[0] if stmt.objects else ""))
        if table not in config.large_tables:
            return False
    if "sql_regex" in match:
        try:
            if not re.search(str(match["sql_regex"]), stmt.raw, flags=re.IGNORECASE | re.MULTILINE):
                return False
        except re.error as exc:
            raise QianshenError(f"规则正则无效: {exc}") from exc
    return True

def _object_for(stmt: StatementInfo) -> str:
    table = str(stmt.attrs.get("table") or "")
    if stmt.attrs.get("dropped_column") and table:
        return f"{table}.{stmt.attrs['dropped_column']}"
    if table:
        return table
    for key in ("dropped_constraint", "securable", "type", "index"):
        if stmt.attrs.get(key):
            return str(stmt.attrs[key])
    return stmt.objects[0] if stmt.objects else stmt.file_rel

def _statement_finding(
    rule: Rule, stmt: StatementInfo, file: FileInfo, config: Config,
    file_statements: list[StatementInfo],
) -> Finding:
    severity = rule.severity
    confidence = "high"
    if stmt.source == "token":
        severity = downgrade_severity(severity)
        confidence = "low"
    object_name = _object_for(stmt)
    values = {
        "file": file.rel_path, "object": object_name, "line": stmt.start_line,
        "version": stmt.version or "", "direction": file.direction, "evidence": stmt.summary,
    }
    return make_finding(
        rule_id=rule.id, title=rule.title, severity=severity, category=rule.category,
        file=file.rel_path, version=stmt.version, direction=file.direction,
        object_name=object_name, evidence=stmt.summary,
        suggestion=_render(rule.suggestion, values),
        source=stmt.source, line_start=stmt.start_line, line_end=stmt.end_line,
        statement_seq=stmt.seq, confidence=confidence, detail=f"stmt:{stmt.sha256}",
    )
def evaluate_rules(
    rules_bundle: RulesBundle,
    files: list[FileInfo],
    statements: list[StatementInfo],
    config: Config,
) -> list[Finding]:
    by_file: dict[str, list[StatementInfo]] = {}
    for stmt in statements:
        by_file.setdefault(stmt.file_rel, []).append(stmt)
    findings: list[Finding] = []
    for rule in rules_bundle.rules:
        if not rule.enabled:
            continue
        check = rule.match.get("check")
        for file in files:
            if file.direction == "unknown" or not _scope_allows(rule, file, config):
                continue
            file_statements = sorted(by_file.get(file.rel_path, []), key=lambda item: item.seq)
            if check:
                findings.extend(file_check_findings(rule, file, file_statements, config))
                continue
            for stmt in file_statements:
                if _match_statement(rule.match, stmt, file, config, file_statements):
                    findings.append(_statement_finding(rule, stmt, file, config, file_statements))
    return findings
