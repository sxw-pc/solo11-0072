"""SQL 语句分类：sqlglot AST 为主，解析失败时降级到保守 token 结果。"""
from __future__ import annotations
import re
from typing import Any
import sqlglot
from sqlglot import ErrorLevel, exp
from .models import FileInfo, StatementInfo
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

def _column_flags(column: exp.ColumnDef) -> tuple[bool, bool]:
    constraints = column.args.get("constraints") or []
    not_null = any(isinstance(c.args.get("kind"), exp.NotNullColumnConstraint) for c in constraints)
    has_default = any(isinstance(c.args.get("kind"), exp.DefaultColumnConstraint) for c in constraints)
    return not_null, has_default

def _column_record(column: exp.ColumnDef) -> dict[str, Any]:
    not_null, has_default = _column_flags(column)
    return {
        "name": column.name,
        "type": descriptor(column.args.get("kind")),
        "not_null": not_null,
        "has_default": has_default,
    }

def _table_name(node: exp.Expression | None) -> str:
    if node is None:
        return ""
    if isinstance(node, exp.Schema):
        node = node.this
    if isinstance(node, (exp.Table, exp.Index)):
        return node.name
    return getattr(node, "name", "") or ""

def _classify_create(ast: exp.Create) -> tuple[str, list[str], dict[str, Any]]:
    kind_word = str(ast.args.get("kind") or "TABLE").lower()
    attrs: dict[str, Any] = {"if_not_exists": bool(ast.args.get("exists"))}
    if kind_word == "index":
        index_name = ast.this.name if isinstance(ast.this, exp.Index) else ""
        table = _table_name(ast.this.args.get("table")) if isinstance(ast.this, exp.Index) else ""
        attrs.update({"index": index_name, "table": table})
        return "create_index", [item for item in (index_name, table) if item], attrs
    table = _table_name(ast.this)
    if table:
        attrs["table"] = table
    if kind_word == "table" and isinstance(ast.this, exp.Schema):
        attrs["columns"] = [
            _column_record(item) for item in ast.this.expressions if isinstance(item, exp.ColumnDef)
        ]
    return f"create_{kind_word}", [table] if table else [], attrs

def _classify_alter(ast: exp.Alter) -> tuple[str, list[str], dict[str, Any]]:
    table = _table_name(ast.this)
    attrs: dict[str, Any] = {
        "table": table, "actions": [], "added_columns": [], "type_alterations": []
    }
    objects = [table] if table else []
    for action in ast.args.get("actions") or []:
        if isinstance(action, exp.ColumnDef):
            record = _column_record(action)
            attrs["actions"].append("add_column")
            attrs["added_columns"].append(record)
            attrs.setdefault("add_column_if_not_exists", bool(action.args.get("exists")))
            objects.extend(filter(None, [f"{table}.{record['name']}"]))
        elif isinstance(action, exp.Drop):
            drop_kind = str(action.args.get("kind") or "").upper()
            target = action.args.get("tables") or []
            name = target[0].name if target else ""
            if drop_kind == "CONSTRAINT":
                attrs["actions"].append("drop_constraint")
                attrs["dropped_constraint"] = name
                objects.append(f"{table}.{name}" if table else name)
            else:
                attrs["actions"].append("drop_column")
                attrs["dropped_column"] = name
                objects.append(f"{table}.{name}" if table else name)
        elif isinstance(action, exp.AlterColumn):
            column_name = action.name
            if isinstance(action.args.get("dtype"), exp.DataType):
                attrs["actions"].append("alter_type")
                attrs["type_alterations"].append(
                    {"column": column_name, "type": descriptor(action.args["dtype"])}
                )
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
    if actions and all(item == "add_column" for item in actions):
        attrs["has_if_not_exists"] = all(
            bool(action.args.get("exists"))
            for action in ast.args.get("actions") or []
            if isinstance(action, exp.ColumnDef)
        )
    return kind, [item for item in objects if item], attrs

def _classify_ast(ast: exp.Expression, sql: str) -> tuple[str, list[str], dict[str, Any]]:
    attrs: dict[str, Any] = {}
    if isinstance(ast, exp.Create):
        return _classify_create(ast)
    if isinstance(ast, exp.Alter):
        return _classify_alter(ast)
    if isinstance(ast, exp.Drop):
        kind_word = str(ast.args.get("kind") or "TABLE").lower()
        objects = [item.name for item in ast.args.get("tables") or [] if getattr(item, "name", "")]
        return f"drop_{kind_word}", objects, {"if_exists": bool(ast.args.get("exists"))}
    if isinstance(ast, exp.TruncateTable):
        objects = [item.name for item in ast.args.get("expressions") or [] if getattr(item, "name", "")]
        return "truncate", objects, {"table": objects[0] if objects else ""}
    if isinstance(ast, (exp.Update, exp.Delete)):
        table = _table_name(ast.this)
        kind = "update" if isinstance(ast, exp.Update) else "delete"
        return kind, [table] if table else [], {
            "table": table, "has_where": ast.args.get("where") is not None
        }
    if isinstance(ast, exp.Insert):
        table = _table_name(ast.this)
        columns: list[str] = []
        if isinstance(ast.this, exp.Schema):
            columns = [item.name for item in ast.this.expressions if getattr(item, "name", "")]
        literals = list(ast.find_all(exp.Literal))
        return "insert", [table] if table else [], {
            "table": table, "insert_columns": columns, "literal_values": len(literals)
        }
    if isinstance(ast, exp.Transaction):
        return "begin", [], attrs
    if isinstance(ast, exp.Commit):
        return "commit", [], attrs
    if isinstance(ast, exp.Rollback):
        return "rollback", [], attrs
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
            parse_ok = False
            parse_warning = "unsupported_statement_form:generic_command"
    else:
        kind, objects, attrs = token_classify(source)
        parse_ok = False
        parse_warning = parse_warning or "parse_error:unknown"
    if not parse_warning and not parse_ok:
        parse_warning = "unsupported_statement_form"
    return StatementInfo(
        file_rel=file.rel_path,
        file_sha256=file.sha256,
        version=file.version,
        direction=file.direction,
        seq=seq,
        start_line=start_line,
        end_line=end_line,
        kind=kind,
        ast_kind=ast_kind,
        objects=sorted(set(objects)),
        actions=list(attrs.get("actions", [])),
        is_ddl=kind in DDL_KINDS,
        is_dml=kind in ("insert", "update", "delete"),
        is_transaction=kind in ("begin", "commit", "rollback"),
        summary=truncate(source, 180),
        sha256=sha256_text(raw.strip()),
        parse_ok=parse_ok,
        parse_warning=parse_warning,
        attrs=attrs,
        raw=raw,
    )

def parse_file(file: FileInfo, dialect: str) -> tuple[list[StatementInfo], list[dict[str, Any]]]:
    statements: list[StatementInfo] = []
    warnings: list[dict[str, Any]] = []
    for index, (raw, start_line, end_line) in enumerate(split_sql(file.text), start=1):
        statement = parse_statement(
            raw, seq=index, start_line=start_line, end_line=end_line, file=file, dialect=dialect
        )
        statements.append(statement)
        if not statement.parse_ok:
            warnings.append(
                {
                    "stage": "parse",
                    "file": file.rel_path,
                    "line": start_line,
                    "statement_seq": index,
                    "code": "parse_fallback",
                    "message": statement.parse_warning or "parse fallback",
                }
            )
    return statements, warnings

def parse_all(
    files: list[FileInfo], dialect: str
) -> tuple[list[StatementInfo], list[dict[str, Any]]]:
    all_statements: list[StatementInfo] = []
    all_warnings: list[dict[str, Any]] = []
    for file in sorted(files, key=lambda item: item.rel_path):
        statements, warnings = parse_file(file, dialect)
        all_statements.extend(statements)
        all_warnings.extend(warnings)
    annotate_type_changes(all_statements)
    return all_statements, all_warnings
