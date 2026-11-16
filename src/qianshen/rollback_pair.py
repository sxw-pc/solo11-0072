"""up/down 回滚配对、对象覆盖与不可逆操作核验。"""
from __future__ import annotations
import re
from collections import defaultdict
from typing import Any
from .config import Config
from .models import FileInfo, Finding, StatementInfo, make_finding
from .sql_split import strip_comments
from .util import QianshenError, downgrade_severity, path_matches, truncate
DESTRUCTIVE = {"drop_table", "drop_column", "truncate"}
APPROVAL_RE = re.compile(
    r"--\s*qianshen:\s*irreversible\s+approved-reason=\"([^\"]+)\"", re.IGNORECASE
)

def _pairing_enabled(config: Config) -> bool:
    pairing = config.raw.get("pairing") or {}
    if not isinstance(pairing, dict):
        raise QianshenError("pairing 配置必须是映射")
    value = pairing.get("check_rollback", True)
    if not isinstance(value, bool):
        raise QianshenError("pairing.check_rollback 必须是布尔值")
    return value

def object_keys(statements: list[StatementInfo]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for stmt in statements:
        table = str(stmt.attrs.get("table") or (stmt.objects[0] if stmt.objects else ""))
        if stmt.kind == "create_table" and table:
            keys.add(("table", table))
            for column in stmt.attrs.get("columns", []):
                if column.get("name"):
                    keys.add(("column", f"{table}.{column['name']}"))
        elif stmt.kind in ("drop_table", "truncate") and table:
            keys.add(("table", table))
        elif stmt.kind == "create_index":
            index = str(stmt.attrs.get("index") or (stmt.objects[0] if stmt.objects else ""))
            if index:
                keys.add(("index", index))
        elif stmt.kind == "drop_index" and stmt.objects:
            keys.add(("index", stmt.objects[0]))
        elif stmt.kind in ("create_view", "drop_view") and stmt.objects:
            keys.add(("view", stmt.objects[0]))
        elif stmt.kind in ("create_type", "alter_type") and stmt.objects:
            keys.add(("type", stmt.objects[0]))
        elif stmt.kind.startswith("alter_table") and table:
            if stmt.attrs.get("dropped_column"):
                keys.add(("column", f"{table}.{stmt.attrs['dropped_column']}"))
            for column in stmt.attrs.get("added_columns", []):
                if column.get("name"):
                    keys.add(("column", f"{table}.{column['name']}"))
            for change in stmt.attrs.get("type_alterations", []):
                if change.get("column"):
                    keys.add(("column", f"{table}.{change['column']}"))
            if stmt.attrs.get("dropped_constraint"):
                keys.add(("constraint", f"{table}.{stmt.attrs['dropped_constraint']}"))
            if "add_constraint" in stmt.actions:
                keys.add(("constraint", table))
            if stmt.attrs.get("renamed_table"):
                keys.add(("table", stmt.attrs["renamed_table"]))
    return keys

def _covered(up_key: tuple[str, str], down_keys: set[tuple[str, str]]) -> bool:
    if up_key in down_keys:
        return True
    kind, name = up_key
    table = name.split(".")[0]
    return kind in ("column", "constraint", "index") and ("table", table) in down_keys

def _source(statements: list[StatementInfo]) -> str:
    return "token" if any(not stmt.parse_ok for stmt in statements) else "ast"

def _severity_for(source: str, severity: str) -> tuple[str, str]:
    if source == "token":
        return downgrade_severity(severity), "low"
    return severity, "high"

def _approved(file: FileInfo, config: Config) -> tuple[bool, str]:
    match = APPROVAL_RE.search(file.text)
    if match:
        return True, match.group(1).strip()
    if any(path_matches(file.rel_path, pattern) for pattern in config.irreversible_approvals):
        return True, "config approval"
    return False, ""

def _destructive_items(statements: list[StatementInfo]) -> list[tuple[StatementInfo, str, str]]:
    result: list[tuple[StatementInfo, str, str]] = []
    for stmt in statements:
        table = str(stmt.attrs.get("table") or (stmt.objects[0] if stmt.objects else ""))
        if stmt.kind == "drop_table" and table:
            result.append((stmt, table, "drop_table"))
        elif stmt.kind == "alter_table_drop_column" and stmt.attrs.get("dropped_column"):
            result.append((stmt, f"{table}.{stmt.attrs['dropped_column']}", "drop_column"))
        elif stmt.kind == "truncate" and table:
            result.append((stmt, table, "truncate"))
    return result
def _finding(
    rule_id: str, title: str, severity: str, file_rel: str, version: int | None,
    direction: str, object_name: str, evidence: str, suggestion: str,
    source: str, stmt: StatementInfo | None, detail: str,
) -> Finding:
    effective, confidence = _severity_for(source, severity)
    return make_finding(
        rule_id=rule_id, title=title, severity=effective, category="rollback",
        file=file_rel, version=version, direction=direction, object_name=object_name,
        evidence=evidence, suggestion=suggestion, source=source,
        line_start=stmt.start_line if stmt else 1, line_end=stmt.end_line if stmt else 1,
        statement_seq=stmt.seq if stmt else None, confidence=confidence, detail=detail,
    )

def check_rollback_pairs(
    files: list[FileInfo], statements: list[StatementInfo], config: Config
) -> tuple[list[Finding], dict[str, Any]]:
    enabled = _pairing_enabled(config)
    by_file: dict[str, list[StatementInfo]] = defaultdict(list)
    for stmt in statements:
        by_file[stmt.file_rel].append(stmt)
    for items in by_file.values():
        items.sort(key=lambda item: item.seq)
    ordered_files = sorted(files, key=lambda item: item.rel_path)
    up_files = {file.version: file for file in ordered_files if file.direction == "up"}
    down_files = {file.version: file for file in ordered_files if file.direction == "down"}
    if not enabled:
        return [], {"enabled": False, "pairs": [], "notices": ["回滚配对检查已由配置关闭。"]}
    if not up_files:
        message = "当前输入没有 up/down 成对文件；单文件模式不执行回滚配对检查。"
        return [], {"enabled": True, "pairs": [], "notices": [message]}
    findings: list[Finding] = []
    pairs: list[dict[str, Any]] = []
    for version in sorted(up_files):
        up = up_files[version]
        down = down_files.get(version)
        up_statements = by_file.get(up.rel_path, [])
        pair: dict[str, Any] = {
            "version": version, "up": up.rel_path, "down": down.rel_path if down else None,
            "status": "ok", "evidence_source": "ast", "up_objects": [],
            "down_objects": [], "missing_objects": [], "extra_objects": [],
            "irreversible_changes": [], "findings": [],
        }
        if down is None:
            finding = _finding(
                "rollback.missing_down", "up 迁移缺少 down 回滚文件", "blocker",
                up.rel_path, version, "up", up.rel_path,
                f"版本 {version} 只有 up 文件 {up.rel_path}",
                "补充对应 down 文件，并确认回滚对象覆盖 up 的主要变更。",
                "file", None, f"missing-down:{version}",
            )
            findings.append(finding)
            pair.update({"status": "missing_down", "evidence_source": "none", "findings": [finding.fingerprint]})
            pairs.append(pair)
            continue
        down_statements = by_file.get(down.rel_path, [])
        down_code = strip_comments(down.text).strip()
        source = _source(up_statements + down_statements)
        if not down_code:
            finding = _finding(
                "rollback.empty_down", "down 回滚文件为空或只有注释", "blocker",
                down.rel_path, version, "down", down.rel_path,
                f"{down.rel_path} 没有可执行语句",
                "补充与 up 对象级变更对应的回滚语句，或在评审记录中说明不适用原因。",
                source, None, f"empty-down:{down.sha256}",
            )
            findings.append(finding)
            pair.update({
                "status": "empty_down",
                "evidence_source": "none" if not down_statements else source,
                "findings": [finding.fingerprint],
            })
            pairs.append(pair)
            continue
        up_keys = object_keys(up_statements)
        down_keys = object_keys(down_statements)
        missing_keys = sorted(key for key in up_keys if not _covered(key, down_keys))
        extra_keys = sorted(key for key in down_keys if not _covered(key, up_keys) and key[0] != "table")
        up_created = {name for kind, name in up_keys if kind == "table"}
        pair.update({
            "up_objects": [f"{kind}:{name}" for kind, name in sorted(up_keys)],
            "down_objects": [f"{kind}:{name}" for kind, name in sorted(down_keys)],
            "missing_objects": [f"{kind}:{name}" for kind, name in missing_keys],
            "extra_objects": [f"{kind}:{name}" for kind, name in extra_keys],
            "evidence_source": source,
        })
        if missing_keys:
            evidence = "down 未覆盖对象: " + ", ".join(f"{kind}:{name}" for kind, name in missing_keys[:6])
            finding = _finding(
                "rollback.object_mismatch", "down 未覆盖 up 的对象级变更", "blocker",
                down.rel_path, version, "down", ", ".join(name for _, name in missing_keys[:3]),
                evidence, "逐项核对表、列、索引、约束、视图与类型，补齐回滚覆盖。",
                source, down_statements[0] if down_statements else None,
                "|".join(sorted(evidence.split())),
            )
            findings.append(finding)
            pair["findings"].append(finding.fingerprint)
        if extra_keys:
            evidence = "down 包含 up 未涉及对象: " + ", ".join(
                f"{kind}:{name}" for kind, name in extra_keys[:6]
            )
            finding = _finding(
                "rollback.down_extra_object", "down 操作了 up 未涉及的对象", "warning",
                down.rel_path, version, "down", ", ".join(name for _, name in extra_keys[:3]),
                evidence, "确认额外回滚操作不会删除或覆盖本次迁移之外的对象。",
                source, None, "|".join(sorted(evidence.split())),
            )
            findings.append(finding)
            pair["findings"].append(finding.fingerprint)
        approved, reason = _approved(up, config)
        for stmt, object_name, action in _destructive_items(up_statements):
            item = {
                "file": up.rel_path, "statement_seq": stmt.seq, "line": stmt.start_line,
                "object": object_name, "action": action, "marker": "irreversible_change",
                "approved": approved, "approved_reason": reason,
            }
            pair["irreversible_changes"].append(item)
            if not approved:
                finding = _finding(
                    "rollback.irreversible_unapproved", "不可逆变更未标记人工确认", "blocker",
                    up.rel_path, version, "up", object_name,
                    f"{action} 对 {object_name} 可能造成数据不可恢复",
                    '如已人工确认，在文件头注释加入 -- qianshen: irreversible approved-reason="demo fixture"；该标记不会跳过其他检查。',
                    stmt.source, stmt, stmt.sha256,
                )
                findings.append(finding)
                pair["findings"].append(finding.fingerprint)
                pair["status"] = "irreversible"
        for stmt, object_name, action in _destructive_items(down_statements):
            if action == "truncate":
                expected = False
            elif action == "drop_table":
                expected = object_name in up_created
            elif action == "drop_column":
                expected = ("column", object_name) in up_keys
            else:
                expected = False
            if expected:
                continue
            finding = _finding(
                "rollback.destructive_in_down", "down 自身包含新的破坏性操作", "warning",
                down.rel_path, version, "down", object_name,
                f"down 中 {action} 作用于 {object_name}，不属于本次 up 的明确逆操作",
                "确认回滚不会破坏迁移之外的数据；必要时拆分为独立迁移。",
                stmt.source, stmt, stmt.sha256,
            )
            findings.append(finding)
            pair["findings"].append(finding.fingerprint)
        if pair["status"] == "ok" and missing_keys:
            pair["status"] = "object_mismatch"
        elif pair["status"] == "ok" and pair["findings"]:
            pair["status"] = "warnings"
        pairs.append(pair)
    counts = {
        "pairs": len(pairs),
        "ok": sum(1 for pair in pairs if pair["status"] == "ok"),
        "issues": sum(1 for pair in pairs if pair["status"] != "ok"),
    }
    return findings, {
        "enabled": True, "pairs": pairs, "counts": counts,
        "notices": [] if pairs else ["没有可核验的 up 版本"],
    }
