"""规则引擎使用的文件级/跨语句检查。"""
from __future__ import annotations
import re
from typing import Any
from .config import Config
from .models import FileInfo, Finding, Rule, StatementInfo, make_finding
from .util import downgrade_severity, truncate
ONLINE_MARKERS = ("qianshen: online", "concurrently", "algorithm=inplace", "online=on")

def _render(template: str, values: dict[str, Any]) -> str:
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError):
        return template

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

def file_check_findings(
    rule: Rule, file: FileInfo, statements: list[StatementInfo], config: Config
) -> list[Finding]:
    check = str(rule.match.get("check"))
    values = {
        "file": file.rel_path, "object": file.rel_path, "line": 1,
        "version": file.version or "", "direction": file.direction, "evidence": "",
    }
    results: list[Finding] = []
    def add(
        stmt: StatementInfo | None, object_name: str, evidence: str, line: int,
        detail: str = "", source: str = "ast",
    ) -> None:
        severity = downgrade_severity(rule.severity) if source == "token" else rule.severity
        confidence = "low" if source == "token" else "high"
        local = dict(values, object=object_name, line=line, evidence=evidence)
        results.append(make_finding(
            rule_id=rule.id, title=rule.title, severity=severity, category=rule.category,
            file=file.rel_path, version=file.version, direction=file.direction,
            object_name=object_name, evidence=evidence, suggestion=_render(rule.suggestion, local),
            source=source, line_start=line, line_end=stmt.end_line if stmt else line,
            statement_seq=stmt.seq if stmt else None, confidence=confidence,
            detail=detail or (stmt.sha256 if stmt else file.sha256),
        ))
    if check == "large_table_ddl_offline":
        for stmt in statements:
            table = str(stmt.attrs.get("table") or "")
            if not table or table not in config.large_tables or not stmt.is_ddl:
                continue
            marker = f"{file.text}\n{stmt.raw}".lower()
            if any(item in marker for item in ONLINE_MARKERS):
                continue
            add(
                stmt, table,
                f"大表 {table} 的 DDL 未声明在线/并发策略: {truncate(stmt.summary, 110)}",
                stmt.start_line, stmt.sha256, stmt.source,
            )
    elif check == "ddl_dml_in_transaction":
        in_tx = False
        current: list[StatementInfo] = []
        for stmt in statements:
            if stmt.kind == "begin":
                in_tx, current = True, [stmt]
            elif in_tx:
                current.append(stmt)
                if stmt.kind in ("commit", "rollback"):
                    if any(item.is_ddl for item in current) and any(item.is_dml for item in current):
                        changed = [item for item in current if item.is_ddl or item.is_dml]
                        source = "token" if any(not item.parse_ok for item in changed) else "ast"
                        begin = next((item for item in current if item.kind == "begin"), current[0])
                        add(
                            begin, file.rel_path,
                            f"同一事务内混合 DDL/DML，共 {len(changed)} 条变更语句",
                            begin.start_line, begin.sha256, source,
                        )
                    in_tx, current = False, []
    elif check == "long_transaction_marker":
        for index, line in enumerate(file.text.splitlines(), start=1):
            if re.search(r"--\s*qianshen:\s*long-transaction\b", line, re.IGNORECASE):
                add(
                    None, file.rel_path,
                    f"文件声明了长事务风险标记: {truncate(line, 100)}",
                    index, f"marker:{index}:{file.sha256}",
                )
    elif check == "duplicate_object":
        seen: dict[str, StatementInfo] = {}
        for stmt in statements:
            table = str(stmt.attrs.get("table") or "")
            definitions: list[str] = []
            if stmt.kind in ("create_table", "create_view", "create_type") and table:
                definitions.append(f"{stmt.kind}:{table}")
            elif stmt.kind == "create_index":
                index = str(stmt.attrs.get("index") or "")
                if index:
                    definitions.append(f"create_index:{index}")
            for column in stmt.attrs.get("added_columns", []):
                if column.get("name"):
                    definitions.append(f"add_column:{table}.{column['name']}")
            for key in definitions:
                if key in seen:
                    source = "token" if not stmt.parse_ok or not seen[key].parse_ok else "ast"
                    add(
                        stmt, key.split(":", 1)[1], f"同一文件重复定义对象: {key.split(':', 1)[1]}",
                        stmt.start_line, f"{seen[key].sha256}:{stmt.sha256}", source,
                    )
                else:
                    seen[key] = stmt
    elif check == "fixed_key_insert":
        for stmt in statements:
            columns = {str(item).lower() for item in stmt.attrs.get("insert_columns", [])}
            if stmt.kind != "insert" or "id" not in columns:
                continue
            if int(stmt.attrs.get("literal_values", 0)) < len(columns):
                continue
            add(
                stmt, _object_for(stmt),
                f"固定主键写入可能重复冲突: {truncate(stmt.summary, 120)}",
                stmt.start_line, stmt.sha256, stmt.source,
            )
    elif check == "non_idempotent_dml":
        for stmt in statements:
            if stmt.kind != "update":
                continue
            if not re.search(
                r"\bset\b[\s\S]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\1\s*[-+]",
                stmt.raw, re.IGNORECASE,
            ):
                continue
            add(
                stmt, _object_for(stmt),
                f"累计更新在重复执行时可能二次生效: {truncate(stmt.summary, 110)}",
                stmt.start_line, stmt.sha256, stmt.source,
            )
    return results
