"""轻量列类型比较与文件内/跨版本类型变更标注。"""
from __future__ import annotations
from typing import Any
from sqlglot import exp
STRING_TYPES = {
    "char", "nchar", "varchar", "nvarchar", "character", "text", "tinytext",
    "mediumtext", "longtext", "string",
}
TEXT_TYPES = {"text", "tinytext", "mediumtext", "longtext"}
INT_RANK = {
    "tinyint": 1, "smallint": 2, "mediumint": 3, "int": 4, "integer": 4,
    "bigint": 5, "serial": 4, "bigserial": 5,
}
FLOAT_RANK = {"real": 1, "float": 2, "double": 3, "double precision": 3}
DECIMAL_TYPES = {"decimal", "numeric", "number"}
TEMPORAL_TYPES = {"date", "datetime", "timestamp", "timestamptz", "time", "timetz"}

def _params(dtype: exp.DataType) -> list[int]:
    values: list[int] = []
    for expression in dtype.expressions:
        literal = expression.this if isinstance(expression, exp.DataTypeParam) else expression
        try:
            values.append(int(literal.name))
        except (TypeError, ValueError):
            continue
    return values

def descriptor(dtype: exp.DataType | None) -> dict[str, Any] | None:
    if dtype is None:
        return None
    raw = dtype.sql().lower()
    name = dtype.this.name.lower()
    params = _params(dtype)
    length = None
    precision = None
    scale = None
    if name in STRING_TYPES:
        family = "string"
        if name not in TEXT_TYPES and params:
            length = params[0]
    elif name in INT_RANK:
        family = "integer"
    elif name in FLOAT_RANK:
        family = "float"
    elif name in DECIMAL_TYPES:
        family = "decimal"
        if params:
            precision = params[0]
            if len(params) > 1:
                scale = params[1]
    elif name in TEMPORAL_TYPES:
        family = "temporal"
    elif name in {"boolean", "bool"}:
        family = "boolean"
    elif name in {"json", "jsonb"}:
        family = "json"
    elif name in {"uuid"}:
        family = "uuid"
    elif name in {"bytea", "blob", "binary", "varbinary"}:
        family = "binary"
        if params:
            length = params[0]
    else:
        family = "other"
    return {
        "raw": raw,
        "family": family,
        "name": name,
        "length": length,
        "precision": precision,
        "scale": scale,
        "rank": INT_RANK.get(name) or FLOAT_RANK.get(name),
    }

def compare_types(old: dict[str, Any] | None, new: dict[str, Any] | None) -> str:
    if not old or not new:
        return "unknown"
    if old.get("raw") == new.get("raw"):
        return "same"
    family = old.get("family")
    if family != new.get("family"):
        return "incompatible"
    if family in ("string", "binary"):
        old_len = old.get("length")
        new_len = new.get("length")
        old_unbounded = old.get("name") in TEXT_TYPES
        new_unbounded = new.get("name") in TEXT_TYPES
        if new_unbounded and not old_unbounded:
            return "widening"
        if old_unbounded and not new_unbounded:
            return "narrowing"
        if old_len is None or new_len is None:
            return "same" if old_len == new_len else ("widening" if old_len is None else "narrowing")
        return "narrowing" if new_len < old_len else ("widening" if new_len > old_len else "same")
    if family in ("integer", "float"):
        old_rank = old.get("rank") or 0
        new_rank = new.get("rank") or 0
        return "narrowing" if new_rank < old_rank else ("widening" if new_rank > old_rank else "same")
    if family == "decimal":
        old_precision = old.get("precision")
        new_precision = new.get("precision")
        old_scale = old.get("scale")
        new_scale = new.get("scale")
        if (
            (old_precision is not None and new_precision is not None and new_precision < old_precision)
            or (old_scale is not None and new_scale is not None and new_scale < old_scale)
        ):
            return "narrowing"
        if (
            (old_precision is not None and new_precision is not None and new_precision > old_precision)
            or (old_scale is not None and new_scale is not None and new_scale > old_scale)
        ):
            return "widening"
        return "unknown"
    if family in ("temporal", "boolean", "json", "uuid"):
        return "incompatible"
    return "unknown"

def _type_descriptor_from_value(value: exp.Expression | None) -> dict[str, Any] | None:
    return descriptor(value) if isinstance(value, exp.DataType) else None

def annotate_type_changes(statements: list[Any]) -> None:
    """按版本顺序维护轻量 schema 状态；只标注能证明的类型收窄/不兼容。"""
    state: dict[str, dict[str, dict[str, Any]]] = {}
    ordered = sorted(
        [stmt for stmt in statements if stmt.direction in ("up", "single")],
        key=lambda item: (item.version if item.version is not None else 0, item.file_rel, item.seq),
    )
    for stmt in ordered:
        table = str(stmt.attrs.get("table") or "")
        if stmt.kind == "create_table" and table:
            state[table] = {
                column["name"]: column.get("type")
                for column in stmt.attrs.get("columns", [])
                if column.get("name") and column.get("type")
            }
        elif stmt.kind == "drop_table" and table:
            state.pop(table, None)
        elif stmt.kind.startswith("alter_table") and table:
            columns = state.setdefault(table, {})
            for column in stmt.attrs.get("added_columns", []):
                if column.get("name"):
                    columns[column["name"]] = column.get("type")
            if stmt.attrs.get("dropped_column"):
                columns.pop(str(stmt.attrs["dropped_column"]), None)
            if stmt.attrs.get("renamed_column"):
                old_name, new_name = stmt.attrs["renamed_column"]
                if old_name in columns:
                    columns[new_name] = columns.pop(old_name)
            if stmt.attrs.get("renamed_table"):
                new_table = str(stmt.attrs["renamed_table"])
                state[new_table] = state.pop(table, {})
            changes: list[dict[str, Any]] = []
            for change in stmt.attrs.get("type_alterations", []):
                column = str(change.get("column") or "")
                old_type = columns.get(column)
                new_type = change.get("type")
                relation = compare_types(old_type, new_type)
                change["old_type"] = old_type
                change["relation"] = relation
                if new_type:
                    columns[column] = new_type
                changes.append({"column": column, "relation": relation, "old": old_type, "new": new_type})
            if changes:
                stmt.attrs["type_changes"] = changes
                stmt.attrs["type_change"] = "narrowing" if any(
                    item["relation"] == "narrowing" for item in changes
                ) else ("incompatible" if any(
                    item["relation"] == "incompatible" for item in changes
                ) else (changes[0]["relation"]))
