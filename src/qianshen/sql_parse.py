"""SQL 语句分类：sqlglot AST 为主，解析失败时降级到保守 token 结果。
解析缓存（路线 B）只复用与文件文本、方言和解析器版本绑定的中性解析事实：
分句结果、AST 分类、attrs 中性字段。跨文件类型状态由 state_layer 每轮
（或按入态检查点增量）重算，type_change/old_type/relation 永不进入解析缓存。
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import sqlglot
from sqlglot import ErrorLevel, exp
from .models import FileInfo, StatementInfo
from .parse_cache import (
    ParseCache, StateCheckpointCache, annotate_with_checkpoints, neutralize_attrs,
)
from .sql_fallback import token_classify
from .sql_split import split_sql, strip_comments
from .type_compare import annotate_type_changes, descriptor
from .util import sha256_text, truncate
DDL_KINDS = {
    "create_table", "alter_table", "alter_table_add_column", "alter_table_drop_column",
    "alter_table_alter_type", "alter_table_set_not_null", "alter_table_drop_not_null",
    "alter_table_set_default", "alter_table_drop_default", "alter_table_add_constraint",
    "alter_table_drop_constraint", "alter_table_rename_table", "alter_table_rename_column",
    "drop_table", "create_index", "drop_index", "truncate", "create_view", "drop_view",
    "create_type", "alter_type",
}
@dataclass
class CacheStats:
    """两层缓存命中/失效计数，供测试与诊断；不进入审计报告与 run_id。"""
    enabled: bool
    cache_dir: str | None
    parse_hits: int = 0
    parse_misses: int = 0
    state_hits: int = 0
    state_misses: int = 0
    io_errors: int = 0
    def to_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "cache_dir": self.cache_dir,
                "parse_hits": self.parse_hits, "parse_misses": self.parse_misses,
                "state_hits": self.state_hits, "state_misses": self.state_misses,
                "io_errors": self.io_errors}
def _column_flags(column: exp.ColumnDef) -> tuple[bool, bool]:
    constraints = column.args.get("constraints") or []
    not_null = any(isinstance(c.args.get("kind"), exp.NotNullColumnConstraint) for c in constraints)
    has_default = any(isinstance(c.args.get("kind"), exp.DefaultColumnConstraint) for c in constraints)
    return not_null, has_default
def _column_record(column: exp.ColumnDef) -> dict[str, Any]:
    not_null, has_default = _column_flags(column)
    return {"name": column.name, "type": descriptor(column.args.get("kind")),
            "not_null": not_null, "has_default": has_default}
def _table_name(node: exp.Expression | None) -> str:
    if isinstance(node, exp.Schema):
        node = node.this
    return getattr(node, "name", "") or "" if node is not None else ""
def _classify_create(ast: exp.Create) -> tuple[str, list[str], dict[str, Any]]:
    kind_word = str(ast.args.get("kind") or "TABLE").lower()
    attrs: dict[str, Any] = {"if_not_exists": bool(ast.args.get("exists"))}
    if kind_word == "index":
        index_name = ast.this.name if isinstance(ast.this, exp.Index) else ""
        table = _table_name(ast.this.args.get("table")) if isinstance(ast.this, exp.Index) else ""
        attrs.update({"index": index_name, "table": table})
        return "create_index", [x for x in (index_name, table) if x], attrs
    table = _table_name(ast.this)
    if table:
        attrs["table"] = table
    if kind_word == "table" and isinstance(ast.this, exp.Schema):
        attrs["columns"] = [
            _column_record(c) for c in ast.this.expressions if isinstance(c, exp.ColumnDef)
        ]
    return f"create_{kind_word}", [table] if table else [], attrs
def _classify_alter(ast: exp.Alter) -> tuple[str, list[str], dict[str, Any]]:
    table = _table_name(ast.this)
    attrs: dict[str, Any] = {
        "table": table, "actions": [], "added_columns": [], "type_alterations": []}
    objects = [table] if table else []
    for action in ast.args.get("actions") or []:
        if isinstance(action, exp.ColumnDef):
            record = _column_record(action)
            attrs["actions"].append("add_column")
            attrs["added_columns"].append(record)
            attrs.setdefault("add_column_if_not_exists", bool(action.args.get("exists")))
            objects.extend(filter(None, [f"{table}.{record['name']}"]))
        elif isinstance(action, exp.Drop):
            kind = str(action.args.get("kind") or "").upper()
            target = action.args.get("tables") or []
            name = target[0].name if target else ""
            if kind == "CONSTRAINT":
                attrs["actions"].append("drop_constraint")
                attrs["dropped_constraint"] = name
            else:
                attrs["actions"].append("drop_column")
                attrs["dropped_column"] = name
            objects.append(f"{table}.{name}" if table else name)
        elif isinstance(action, exp.AlterColumn):
            column_name = action.name
            if isinstance(action.args.get("dtype"), exp.DataType):
                attrs["actions"].append("alter_type")
                attrs["type_alterations"].append(
                    {"column": column_name, "type": descriptor(action.args["dtype"])})
                objects.append(f"{table}.{column_name}" if table else column_name)
            elif action.args.get("default") is not None:
                attrs["actions"].append("set_default")
            elif action.args.get("drop") and action.args.get("allow_null") is True:
                attrs["actions"].append("drop_not_null")
            elif action.args.get("allow_null") is False:
                attrs["actions"].append("set_not_null")
            elif action.args.get("drop"):
                attrs["actions"].append("drop_default")
            else:
                attrs["actions"].append("alter_column")
        elif isinstance(action, exp.AlterRename):
            attrs["actions"].append("rename_table")
            attrs["renamed_table"] = _table_name(action.this)
        elif isinstance(action, exp.RenameColumn):
            attrs["actions"].append("rename_column")
            attrs["renamed_column"] = [action.name, _table_name(action.args.get("to"))]
        elif isinstance(action, exp.AddConstraint):
            attrs["actions"].append("add_constraint")
        else:
            attrs["actions"].append("other")
    actions = attrs["actions"]
    kind = f"alter_table_{actions[0]}" if len(actions) == 1 else "alter_table"
    if actions and all(a == "add_column" for a in actions):
        attrs["has_if_not_exists"] = all(
            bool(a.args.get("exists")) for a in ast.args.get("actions") or []
            if isinstance(a, exp.ColumnDef))
    return kind, [o for o in objects if o], attrs
def _classify_ast(ast: exp.Expression, sql: str) -> tuple[str, list[str], dict[str, Any]]:
    if isinstance(ast, exp.Create):
        return _classify_create(ast)
    if isinstance(ast, exp.Alter):
        return _classify_alter(ast)
    if isinstance(ast, exp.Drop):
        kind_word = str(ast.args.get("kind") or "TABLE").lower()
        objects = [t.name for t in ast.args.get("tables") or [] if getattr(t, "name", "")]
        return f"drop_{kind_word}", objects, {"if_exists": bool(ast.args.get("exists"))}
    if isinstance(ast, exp.TruncateTable):
        objects = [t.name for t in ast.args.get("expressions") or [] if getattr(t, "name", "")]
        return "truncate", objects, {"table": objects[0] if objects else ""}
    if isinstance(ast, (exp.Update, exp.Delete)):
        table = _table_name(ast.this)
        return ("update" if isinstance(ast, exp.Update) else "delete",
                [table] if table else [],
                {"table": table, "has_where": ast.args.get("where") is not None})
    if isinstance(ast, exp.Insert):
        table = _table_name(ast.this)
        columns = [c.name for c in ast.this.expressions if getattr(c, "name", "")] \
            if isinstance(ast.this, exp.Schema) else []
        return "insert", [table] if table else [], {
            "table": table, "insert_columns": columns, "literal_values": len(list(ast.find_all(exp.Literal)))}
    tx = {exp.Transaction: "begin", exp.Commit: "commit", exp.Rollback: "rollback"}
    for node_type, name in tx.items():
        if isinstance(ast, node_type):
            return name, [], {}
    if isinstance(ast, (exp.Grant, exp.Revoke)):
        securable = _table_name(ast.args.get("securable"))
        kind = "grant" if isinstance(ast, exp.Grant) else "revoke"
        return kind, [securable] if securable else [], {"securable": securable}
    if isinstance(ast, exp.Command) and re.match(r"(?is)^\s*ALTER\s+TYPE\b", sql):
        match = re.search(r"(?is)^\s*ALTER\s+TYPE\s+([\w.\"]+)", sql)
        name = match.group(1).strip('"') if match else ""
        return "alter_type", [name] if name else [], {"type": name}
    return "other", [], {}
def parse_statement(
    raw: str, *, seq: int, start_line: int, end_line: int, file: FileInfo, dialect: str
) -> StatementInfo:
    source = strip_comments(raw).strip()
    parse_warning: str | None = None
    ast_kind = ""
    try:
        ast = sqlglot.parse_one(source, read=dialect, error_level=ErrorLevel.IGNORE)
    except Exception as exc:  # 不同 sqlglot 版本的异常类型不同
        ast = None
        parse_warning = f"parse_error:{type(exc).__name__}:{truncate(str(exc), 100)}"
    if ast is not None:
        ast_kind = type(ast).__name__
        kind, objects, attrs = _classify_ast(ast, source)
        parse_ok = kind != "other" or isinstance(ast, exp.Command)
        if isinstance(ast, exp.Command) and kind == "other":
            parse_ok, parse_warning = False, "unsupported_statement_form:generic_command"
    else:
        kind, objects, attrs = token_classify(source)
        parse_ok, parse_warning = False, parse_warning or "parse_error:unknown"
    if not parse_warning and not parse_ok:
        parse_warning = "unsupported_statement_form"
    return StatementInfo(
        file_rel=file.rel_path, file_sha256=file.sha256, version=file.version,
        direction=file.direction, seq=seq, start_line=start_line, end_line=end_line,
        kind=kind, ast_kind=ast_kind, objects=sorted(set(objects)),
        actions=list(attrs.get("actions", [])), is_ddl=kind in DDL_KINDS,
        is_dml=kind in ("insert", "update", "delete"),
        is_transaction=kind in ("begin", "commit", "rollback"),
        summary=truncate(source, 180), sha256=sha256_text(raw.strip()),
        parse_ok=parse_ok, parse_warning=parse_warning, attrs=attrs, raw=raw,
    )
# 与路径/版本无关、允许进入解析缓存的字段；路径绑定字段一律重新绑定。
_NEUTRAL_FIELDS = (
    "seq", "start_line", "end_line", "kind", "ast_kind", "objects", "actions",
    "is_ddl", "is_dml", "is_transaction", "summary", "sha256", "parse_ok",
    "parse_warning", "attrs", "raw",
)
def _neutral(statement: StatementInfo) -> dict[str, Any]:
    data = {field: getattr(statement, field) for field in _NEUTRAL_FIELDS}
    data["objects"], data["actions"] = list(statement.objects), list(statement.actions)
    data["attrs"] = neutralize_attrs(statement.attrs)
    return data
def _bind(data: dict[str, Any], file: FileInfo) -> StatementInfo:
    return StatementInfo(
        file_rel=file.rel_path, file_sha256=file.sha256, version=file.version,
        direction=file.direction, seq=int(data["seq"]), start_line=int(data["start_line"]),
        end_line=int(data["end_line"]), kind=str(data["kind"]),
        ast_kind=str(data.get("ast_kind", "")), objects=list(data.get("objects", [])),
        actions=list(data.get("actions", [])), is_ddl=bool(data["is_ddl"]),
        is_dml=bool(data["is_dml"]), is_transaction=bool(data["is_transaction"]),
        summary=str(data["summary"]), sha256=str(data["sha256"]),
        parse_ok=bool(data["parse_ok"]), parse_warning=data.get("parse_warning"),
        attrs=neutralize_attrs(data.get("attrs") or {}), raw=str(data.get("raw", "")),
    )
def _warnings(file: FileInfo, statements: list[StatementInfo]) -> list[dict[str, Any]]:
    return [{"stage": "parse", "file": file.rel_path, "line": s.start_line,
             "statement_seq": s.seq, "code": "parse_fallback",
             "message": s.parse_warning or "parse fallback"}
            for s in statements if not s.parse_ok]
def parse_file(
    file: FileInfo, dialect: str, cache: ParseCache | None = None
) -> tuple[list[StatementInfo], list[dict[str, Any]]]:
    key = ParseCache.entry_key(file.sha256, dialect) if cache is not None and cache.enabled else None
    if key is not None:
        payload = cache.get(key, file.sha256, dialect)
        if payload is not None:
            statements = [_bind(item, file) for item in payload["statements"]]
            # 命中后自检原始 SQL 摘要，防止损坏/伪造条目带入不匹配文本。
            if all(s.sha256 == sha256_text(s.raw.strip()) for s in statements):
                return statements, _warnings(file, statements)
            cache.errors += 1
    statements = [
        parse_statement(raw, seq=i, start_line=sl, end_line=el, file=file, dialect=dialect)
        for i, (raw, sl, el) in enumerate(split_sql(file.text), start=1)
    ]
    if key is not None:
        cache.put(key, file_sha256=file.sha256, dialect=dialect,
                  statements=[_neutral(s) for s in statements])
    return statements, _warnings(file, statements)
def parse_all(
    files: list[FileInfo],
    dialect: str,
    cache_dir: str | Path | None = None,
    stats: CacheStats | None = None,
) -> tuple[list[StatementInfo], list[dict[str, Any]]]:
    root = Path(cache_dir) if cache_dir is not None else None
    parse_cache, state_cache = ParseCache(root), StateCheckpointCache(root)
    if stats is None:
        stats = CacheStats(cache_dir is not None, str(cache_dir) if cache_dir else None)
    all_statements: list[StatementInfo] = []
    all_warnings: list[dict[str, Any]] = []
    parse_keys: dict[str, str] = {}
    for file in sorted(files, key=lambda f: f.rel_path):
        parse_keys[file.rel_path] = ParseCache.entry_key(file.sha256, dialect)
        stmts, warns = parse_file(file, dialect, parse_cache)
        all_statements.extend(stmts)
        all_warnings.extend(warns)
    if root is not None:
        stats.state_hits, stats.state_misses = annotate_with_checkpoints(
            all_statements, parse_keys.__getitem__, state_cache)
    else:
        annotate_type_changes(all_statements)
    stats.parse_hits, stats.parse_misses = parse_cache.hits, parse_cache.misses
    stats.io_errors += parse_cache.errors + state_cache.errors
    return all_statements, all_warnings
