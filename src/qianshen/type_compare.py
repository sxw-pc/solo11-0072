"""轻量列类型比较与文件内/跨版本类型变更标注。"""
from __future__ import annotations
import copy
from typing import Any
from sqlglot import exp
from .cache import canonical_state, parse_identity, state_digest
from .util import canonical_json
STRING_TYPES = {
    "char", "nchar", "varchar", "nvarchar", "character", "text", "tinytext", "mediumtext", "longtext", "string",
}
TEXT_TYPES = {"text", "tinytext", "mediumtext", "longtext"}
INT_RANK = {
    "tinyint": 1, "smallint": 2, "mediumint": 3, "int": 4, "integer": 4, "bigint": 5, "serial": 4, "bigserial": 5,
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
    length = precision = scale = None
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
        "raw": raw, "family": family, "name": name, "length": length,
        "precision": precision, "scale": scale,
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
        narrower = (
            (old_precision is not None and new_precision is not None and new_precision < old_precision)
            or (old_scale is not None and new_scale is not None and new_scale < old_scale)
        )
        wider = (
            (old_precision is not None and new_precision is not None and new_precision > old_precision)
            or (old_scale is not None and new_scale is not None and new_scale > old_scale)
        )
        return "narrowing" if narrower else ("widening" if wider else "unknown")
    if family in ("temporal", "boolean", "json", "uuid"):
        return "incompatible"
    return "unknown"

def _ordered_up_statements(statements: list[Any]) -> list[Any]:
    key = lambda item: (item.version if item.version is not None else 0, item.file_rel, item.seq)
    return sorted([s for s in statements if s.direction in ("up", "single")], key=key)

def _process_statement(
    state: dict[str, dict[str, dict[str, Any]]], stmt: Any
) -> tuple[dict[str, Any] | None, bool]:
    """推进单条语句的类型状态；返回 (annotation, identity_ok)。

    identity_ok 为 False 表示对象身份无法解析，其后状态不得参与检查点复用。
    """
    table = str(stmt.attrs.get("table") or "")
    if stmt.kind == "create_table":
        if not table:
            return None, False
        state[table] = {
            column["name"]: column.get("type")
            for column in stmt.attrs.get("columns", [])
            if column.get("name") and column.get("type")
        }
        return None, True
    if stmt.kind == "drop_table":
        if not table:
            return None, False
        state.pop(table, None)
        return None, True
    if not stmt.kind.startswith("alter_table"):
        return None, True
    if not table:
        return None, False
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
        state[str(stmt.attrs["renamed_table"])] = state.pop(table, {})
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
    if not changes:
        return None, True
    stmt.attrs["type_changes"] = changes
    relations = {item["relation"] for item in changes}
    stmt.attrs["type_change"] = (
        "narrowing" if "narrowing" in relations
        else "incompatible" if "incompatible" in relations
        else changes[0]["relation"]
    )
    return {
        "type_alterations": copy.deepcopy(stmt.attrs["type_alterations"]),
        "type_changes": copy.deepcopy(changes), "type_change": stmt.attrs["type_change"],
    }, True

def annotate_type_changes(statements: list[Any]) -> None:
    """按版本顺序维护轻量 schema 状态；只标注能证明的类型收窄/不兼容。"""
    state: dict[str, dict[str, dict[str, Any]]] = {}
    for stmt in _ordered_up_statements(statements):
        _process_statement(state, stmt)

def _file_is_clean(file_statements: list[Any]) -> bool:
    """token 回退可能隐藏状态变更：含未解析语句的文件不参与检查点复用。"""
    return all(stmt.parse_ok for stmt in file_statements)

def _matching_record(
    state_cache: Any, file_statements: list[Any], rel_path: str,
    in_canonical: dict[str, Any], in_digest: str, dialect: str,
) -> dict[str, Any] | None:
    """核对检查点记录的全部输入依赖；任何一项不符都禁止命中。"""
    first = file_statements[0]
    candidate = state_cache.lookup(first.file_sha256, in_digest)
    if not isinstance(candidate, dict):
        return None
    try:
        sort_key = [first.version if first.version is not None else 0, rel_path]
        stored_in = candidate.get("in_state")
        out_state = candidate.get("out_state")
        annotations = candidate.get("annotations")
        if candidate.get("parse_key") != parse_identity(first.file_sha256, dialect):
            return None
        if list(candidate.get("sort_key") or []) != sort_key:
            return None
        if list(candidate.get("statement_kinds") or []) != [s.kind for s in file_statements]:
            return None
        if not isinstance(stored_in, dict) or not isinstance(out_state, dict):
            return None
        # 摘要命中后仍核对完整规范化入态，不允许靠摘要猜测收敛
        if canonical_json(canonical_state(stored_in)) != canonical_json(in_canonical):
            return None
        canonical_state(out_state)
        required = ("type_alterations", "type_changes", "type_change")
        if not isinstance(annotations, dict) or any(
            not isinstance(value, dict) or any(key not in value for key in required)
            for value in annotations.values()
        ):
            return None
        expected = {str(s.seq) for s in file_statements if s.attrs.get("type_alterations")}
        return candidate if set(annotations) == expected else None
    except (TypeError, ValueError, KeyError):
        return None

def _apply_record(record: dict[str, Any], file_statements: list[Any]) -> None:
    for stmt in file_statements:
        annotation = record["annotations"].get(str(stmt.seq))
        if annotation is not None:
            stmt.attrs["type_alterations"] = copy.deepcopy(annotation["type_alterations"])
            stmt.attrs["type_changes"] = copy.deepcopy(annotation["type_changes"])
            stmt.attrs["type_change"] = annotation["type_change"]

def _build_record(
    file_statements: list[Any], rel_path: str, in_canonical: dict[str, Any],
    in_digest: str, out_state: dict[str, dict[str, Any]],
    annotations: dict[str, dict[str, Any]], dialect: str,
) -> dict[str, Any]:
    first = file_statements[0]
    return {
        "parse_key": parse_identity(first.file_sha256, dialect),
        "file_sha256": first.file_sha256,
        "sort_key": [first.version if first.version is not None else 0, rel_path],
        "in_state_digest": in_digest,
        "in_state": copy.deepcopy(in_canonical),
        "out_state": canonical_state(copy.deepcopy(out_state)),
        "annotations": copy.deepcopy(annotations),
        "statement_kinds": [stmt.kind for stmt in file_statements],
    }

def annotate_type_changes_incremental(
    statements: list[Any], state_cache: Any, dialect: str
) -> None:
    """带每文件入态/出态检查点的增量类型标注。

    仅当文件本轮解析身份与文件开始时的完整类型状态都和检查点一致时，才复用
    旧的 type_change 标注；否则从该文件起向后重算直到状态重新收敛。对象身份
    无法解析、token 回退、排序键变化或状态无法规范化比较时失效到文件链末端。
    """
    by_file: dict[str, list[Any]] = {}
    for stmt in _ordered_up_statements(statements):
        by_file.setdefault(stmt.file_rel, []).append(stmt)
    state: dict[str, dict[str, dict[str, Any]]] = {}
    broken = False
    for rel_path, file_statements in by_file.items():
        clean = _file_is_clean(file_statements)
        in_canonical: dict[str, Any] | None = None
        in_digest, state_ok = "", False
        try:
            in_canonical = canonical_state(state)
            in_digest = state_digest(state)
            state_ok = True
        except (TypeError, ValueError):
            broken = True
        record = None
        if not broken and clean and state_ok:
            record = _matching_record(
                state_cache, file_statements, rel_path, in_canonical, in_digest, dialect
            )
        if record is not None:
            _apply_record(record, file_statements)
            state = copy.deepcopy(record["out_state"])
            continue
        annotations: dict[str, dict[str, Any]] = {}
        identity_ok = True
        for stmt in file_statements:
            annotation, stmt_ok = _process_statement(state, stmt)
            identity_ok = identity_ok and stmt_ok
            if annotation is not None:
                annotations[str(stmt.seq)] = annotation
        if clean and identity_ok and state_ok:
            try:
                state_cache.store(_build_record(
                    file_statements, rel_path, in_canonical, in_digest,
                    state, annotations, dialect,
                ))
            except (TypeError, ValueError):
                broken = True
        if not clean or not identity_ok:
            broken = True
