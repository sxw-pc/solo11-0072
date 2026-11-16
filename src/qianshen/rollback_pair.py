"""up/down 回滚配对、对象覆盖与不可逆操作核验。"""
from __future__ import annotations
import re
from collections import defaultdict
from typing import Any
from .config import Config
from .models import FileInfo, Finding, StatementInfo, make_finding
from .sql_split import strip_comments
from .util import QianshenError, downgrade_severity, path_matches
DESTRUCTIVE = {"drop_table", "drop_column", "truncate"}
APPROVAL_RE = re.compile(r"--\s*qianshen:\s*irreversible\s+approved-reason=\"([^\"]+)\"", re.IGNORECASE)

def _pairing_enabled(config: Config) -> bool:
    pairing = config.raw.get("pairing") or {}
    if not isinstance(pairing, dict):
        raise QianshenError("pairing 配置必须是映射")
    value = pairing.get("check_rollback", True)
    if not isinstance(value, bool):
        raise QianshenError("pairing.check_rollback 必须是布尔值")
    return value

def _table(stmt: StatementInfo) -> str:
    return str(stmt.attrs.get("table") or (stmt.objects[0] if stmt.objects else ""))

def object_keys(statements: list[StatementInfo]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for s in statements:
        table = _table(s)
        if s.kind == "create_table" and table:
            keys.add(("table", table))
            keys.update(("column", f"{table}.{c['name']}") for c in s.attrs.get("columns", []) if c.get("name"))
        elif s.kind in ("drop_table", "truncate") and table:
            keys.add(("table", table))
        elif s.kind == "create_index":
            index = str(s.attrs.get("index") or (s.objects[0] if s.objects else ""))
            if index:
                keys.add(("index", index))
        elif s.kind == "drop_index" and s.objects:
            keys.add(("index", s.objects[0]))
        elif s.kind in ("create_view", "drop_view") and s.objects:
            keys.add(("view", s.objects[0]))
        elif s.kind in ("create_type", "alter_type") and s.objects:
            keys.add(("type", s.objects[0]))
        elif s.kind.startswith("alter_table") and table:
            if s.attrs.get("dropped_column"):
                keys.add(("column", f"{table}.{s.attrs['dropped_column']}"))
            keys.update(("column", f"{table}.{c['name']}")
                        for c in s.attrs.get("added_columns", []) if c.get("name"))
            keys.update(("column", f"{table}.{c['column']}")
                        for c in s.attrs.get("type_alterations", []) if c.get("column"))
            if s.attrs.get("dropped_constraint"):
                keys.add(("constraint", f"{table}.{s.attrs['dropped_constraint']}"))
            if "add_constraint" in s.actions:
                keys.add(("constraint", table))
            if s.attrs.get("renamed_table"):
                keys.add(("table", s.attrs["renamed_table"]))
    return keys

def _covered(up_key: tuple[str, str], down_keys: set[tuple[str, str]]) -> bool:
    if up_key in down_keys:
        return True
    kind, name = up_key
    table = name.split(".")[0]
    return kind in ("column", "constraint", "index") and ("table", table) in down_keys

def _source(statements: list[StatementInfo]) -> str:
    return "token" if any(not s.parse_ok for s in statements) else "ast"

def _approved(file: FileInfo, config: Config) -> tuple[bool, str]:
    match = APPROVAL_RE.search(file.text)
    if match:
        return True, match.group(1).strip()
    if any(path_matches(file.rel_path, p) for p in config.irreversible_approvals):
        return True, "config approval"
    return False, ""

def _destructive_items(statements):
    result = []
    for s in statements:
        table = _table(s)
        if s.kind == "drop_table" and table:
            result.append((s, table, "drop_table"))
        elif s.kind == "alter_table_drop_column" and s.attrs.get("dropped_column"):
            result.append((s, f"{table}.{s.attrs['dropped_column']}", "drop_column"))
        elif s.kind == "truncate" and table:
            result.append((s, table, "truncate"))
    return result

def _finding(rule_id, title, severity, file_rel, version, direction, obj, evidence,
             suggestion, source, stmt, detail) -> Finding:
    effective = downgrade_severity(severity) if source == "token" else severity
    return make_finding(
        rule_id=rule_id, title=title, severity=effective, category="rollback", file=file_rel,
        version=version, direction=direction, object_name=obj, evidence=evidence,
        suggestion=suggestion, source=source,
        line_start=stmt.start_line if stmt else 1, line_end=stmt.end_line if stmt else 1,
        statement_seq=stmt.seq if stmt else None,
        confidence="low" if source == "token" else "high", detail=detail,
    )

def check_rollback_pairs(files, statements, config: Config):
    enabled = _pairing_enabled(config)
    by_file: dict[str, list[StatementInfo]] = defaultdict(list)
    for s in statements:
        by_file[s.file_rel].append(s)
    for items in by_file.values():
        items.sort(key=lambda x: x.seq)
    ordered = sorted(files, key=lambda f: f.rel_path)
    up_files = {f.version: f for f in ordered if f.direction == "up"}
    down_files = {f.version: f for f in ordered if f.direction == "down"}
    if not enabled:
        return [], {"enabled": False, "pairs": [], "notices": ["回滚配对检查已由配置关闭。"]}
    if not up_files:
        return [], {"enabled": True, "pairs": [],
                    "notices": ["当前输入没有 up/down 成对文件；单文件模式不执行回滚配对检查。"]}
    findings: list[Finding] = []
    pairs: list[dict[str, Any]] = []
    for version in sorted(up_files):
        up = up_files[version]
        down = down_files.get(version)
        up_stmts = by_file.get(up.rel_path, [])
        pair = {"version": version, "up": up.rel_path, "down": down.rel_path if down else None,
                "status": "ok", "evidence_source": "ast", "up_objects": [], "down_objects": [],
                "missing_objects": [], "extra_objects": [], "irreversible_changes": [], "findings": []}
        if down is None:
            f = _finding("rollback.missing_down", "up 迁移缺少 down 回滚文件", "blocker",
                up.rel_path, version, "up", up.rel_path,
                f"版本 {version} 只有 up 文件 {up.rel_path}",
                "补充对应 down 文件，并确认回滚对象覆盖 up 的主要变更。",
                "file", None, f"missing-down:{version}")
            findings.append(f)
            pair.update({"status": "missing_down", "evidence_source": "none", "findings": [f.fingerprint]})
            pairs.append(pair)
            continue
        down_stmts = by_file.get(down.rel_path, [])
        source = _source(up_stmts + down_stmts)
        if not strip_comments(down.text).strip():
            f = _finding("rollback.empty_down", "down 回滚文件为空或只有注释", "blocker",
                down.rel_path, version, "down", down.rel_path, f"{down.rel_path} 没有可执行语句",
                "补充与 up 对象级变更对应的回滚语句，或在评审记录中说明不适用原因。",
                source, None, f"empty-down:{down.sha256}")
            findings.append(f)
            pair.update({"status": "empty_down",
                         "evidence_source": "none" if not down_stmts else source, "findings": [f.fingerprint]})
            pairs.append(pair)
            continue
        up_keys, down_keys = object_keys(up_stmts), object_keys(down_stmts)
        missing = sorted(k for k in up_keys if not _covered(k, down_keys))
        extra = sorted(k for k in down_keys if not _covered(k, up_keys) and k[0] != "table")
        up_created = {name for kind, name in up_keys if kind == "table"}
        pair.update({
            "up_objects": [f"{k}:{n}" for k, n in sorted(up_keys)],
            "down_objects": [f"{k}:{n}" for k, n in sorted(down_keys)],
            "missing_objects": [f"{k}:{n}" for k, n in missing],
            "extra_objects": [f"{k}:{n}" for k, n in extra], "evidence_source": source})
        if missing:
            ev = "down 未覆盖对象: " + ", ".join(f"{k}:{n}" for k, n in missing[:6])
            f = _finding("rollback.object_mismatch", "down 未覆盖 up 的对象级变更", "blocker",
                down.rel_path, version, "down", ", ".join(n for _, n in missing[:3]), ev,
                "逐项核对表、列、索引、约束、视图与类型，补齐回滚覆盖。",
                source, down_stmts[0] if down_stmts else None, "|".join(sorted(ev.split())))
            findings.append(f); pair["findings"].append(f.fingerprint)
        if extra:
            ev = "down 包含 up 未涉及对象: " + ", ".join(f"{k}:{n}" for k, n in extra[:6])
            f = _finding("rollback.down_extra_object", "down 操作了 up 未涉及的对象", "warning",
                down.rel_path, version, "down", ", ".join(n for _, n in extra[:3]), ev,
                "确认额外回滚操作不会删除或覆盖本次迁移之外的对象。",
                source, None, "|".join(sorted(ev.split())))
            findings.append(f); pair["findings"].append(f.fingerprint)
        approved, reason = _approved(up, config)
        for stmt, obj, action in _destructive_items(up_stmts):
            pair["irreversible_changes"].append({"file": up.rel_path, "statement_seq": stmt.seq,
                "line": stmt.start_line, "object": obj, "action": action,
                "marker": "irreversible_change", "approved": approved, "approved_reason": reason})
            if not approved:
                f = _finding("rollback.irreversible_unapproved", "不可逆变更未标记人工确认", "blocker",
                    up.rel_path, version, "up", obj, f"{action} 对 {obj} 可能造成数据不可恢复",
                    '如已人工确认，在文件头注释加入 -- qianshen: irreversible approved-reason="demo fixture"；该标记不会跳过其他检查。',
                    stmt.source, stmt, stmt.sha256)
                findings.append(f); pair["findings"].append(f.fingerprint); pair["status"] = "irreversible"
        for stmt, obj, action in _destructive_items(down_stmts):
            expected = (action == "drop_table" and obj in up_created) or (
                action == "drop_column" and ("column", obj) in up_keys)
            if expected:
                continue
            f = _finding("rollback.destructive_in_down", "down 自身包含新的破坏性操作", "warning",
                down.rel_path, version, "down", obj,
                f"down 中 {action} 作用于 {obj}，不属于本次 up 的明确逆操作",
                "确认回滚不会破坏迁移之外的数据；必要时拆分为独立迁移。",
                stmt.source, stmt, stmt.sha256)
            findings.append(f); pair["findings"].append(f.fingerprint)
        if pair["status"] == "ok" and missing:
            pair["status"] = "object_mismatch"
        elif pair["status"] == "ok" and pair["findings"]:
            pair["status"] = "warnings"
        pairs.append(pair)
    counts = {"pairs": len(pairs), "ok": sum(1 for p in pairs if p["status"] == "ok"),
              "issues": sum(1 for p in pairs if p["status"] != "ok")}
    return findings, {"enabled": True, "pairs": pairs, "counts": counts,
                      "notices": [] if pairs else ["没有可核验的 up 版本"]}
