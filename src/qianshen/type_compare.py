"""轻量列类型比较与文件内/跨版本类型变更标注。"""
from __future__ import annotations
import copy
from typing import Any
from sqlglot import exp
from .util import canonical_json
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
    length = precision = scale = None
    families = [
        (STRING_TYPES, "string"), (INT_RANK, "integer"), (FLOAT_RANK, "float"),
        (DECIMAL_TYPES, "decimal"), (TEMPORAL_TYPES, "temporal"),
        ({"boolean", "bool"}, "boolean"), ({"json", "jsonb"}, "json"),
        ({"uuid"}, "uuid"), ({"bytea", "blob", "binary", "varbinary"}, "binary"),
    ]
    family = next((label for group, label in families if name in group), "other")
    if family == "string" and name not in TEXT_TYPES and params:
        length = params[0]
    elif family == "decimal" and params:
        precision, scale = params[0], params[1] if len(params) > 1 else None
    elif family == "binary" and params:
        length = params[0]
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
        old_len, new_len = old.get("length"), new.get("length")
        old_unbounded, new_unbounded = old.get("name") in TEXT_TYPES, new.get("name") in TEXT_TYPES
        if new_unbounded and not old_unbounded:
            return "widening"
        if old_unbounded and not new_unbounded:
            return "narrowing"
        if old_len is None or new_len is None:
            return "same" if old_len == new_len else ("widening" if old_len is None else "narrowing")
        return "narrowing" if new_len < old_len else ("widening" if new_len > old_len else "same")
    if family in ("integer", "float"):
        old_rank, new_rank = old.get("rank") or 0, new.get("rank") or 0
        return "narrowing" if new_rank < old_rank else ("widening" if new_rank > old_rank else "same")
    if family == "decimal":
        pairs = [(old.get("precision"), new.get("precision")),
                 (old.get("scale"), new.get("scale"))]
        if any(a is not None and b is not None and b < a for a, b in pairs):
            return "narrowing"
        if any(a is not None and b is not None and b > a for a, b in pairs):
            return "widening"
        return "unknown"
    if family in ("temporal", "boolean", "json", "uuid"):
        return "incompatible"
    return "unknown"
def canonicalize_state(state: dict[str, dict[str, dict[str, Any]]]) -> str:
    """完整规范化状态快照（非摘要）：表->列限定身份与完整类型描述全部参与。"""
    return canonical_json(state)
def _blank(stmt: Any) -> None:
    stmt.attrs.pop("type_change", None)
    stmt.attrs.pop("type_changes", None)
    for item in stmt.attrs.get("type_alterations", []):
        if isinstance(item, dict):
            item.pop("old_type", None)
            item.pop("relation", None)
def _order_key(stmt: Any) -> tuple[Any, ...]:
    return (stmt.version if stmt.version is not None else 0, stmt.file_rel, stmt.seq)
class TypeStateEngine:
    """按 (version,file_rel,seq) 维护跨文件类型状态；apply_file 现场推演，
    replay_file 在入态与解析身份完全一致时复用检查点。poisoned 表示遇到
    token 降级或无法规范化的对象身份，调用方须毒化到链末端、停用检查点。"""
    def __init__(self) -> None:
        self.state: dict[str, dict[str, dict[str, Any]]] = {}
        self.poisoned = False
    def snapshot_in(self) -> str:
        return canonicalize_state(self.state)
    def _structural(self, stmt: Any) -> bool:
        """应用建表/删表/增删改列等结构变化，返回是否存在无法解析的身份。"""
        table = str(stmt.attrs.get("table") or "")
        if stmt.kind == "create_table":
            if not table:
                return True
            self.state[table] = {
                col["name"]: copy.deepcopy(col.get("type"))
                for col in stmt.attrs.get("columns", []) if col.get("name") and col.get("type")
            }
            return False
        if stmt.kind == "drop_table":
            if not table:
                return True
            self.state.pop(table, None)
            return False
        if not stmt.kind.startswith("alter_table"):
            return False
        if not table:
            return True
        columns = self.state.setdefault(table, {})
        for col in stmt.attrs.get("added_columns", []):
            if not col.get("name"):
                return True
            columns[col["name"]] = copy.deepcopy(col.get("type"))
        if stmt.attrs.get("dropped_column"):
            columns.pop(str(stmt.attrs["dropped_column"]), None)
        if stmt.attrs.get("renamed_column"):
            old_name, new_name = stmt.attrs["renamed_column"]
            if not new_name:
                return True
            if old_name in columns:
                columns[new_name] = columns.pop(old_name)
        if stmt.attrs.get("renamed_table"):
            new_table = str(stmt.attrs["renamed_table"])
            if not new_table:
                return True
            self.state[new_table] = self.state.pop(table, {})
        return False
    def _annotate_types(self, stmt: Any) -> bool:
        bad = False
        changes: list[dict[str, Any]] = []
        columns = self.state.setdefault(str(stmt.attrs.get("table") or ""), {})
        for change in stmt.attrs.get("type_alterations", []):
            column = str(change.get("column") or "")
            if not column:
                bad = True
                continue
            old_type = copy.deepcopy(columns.get(column))
            new_type = copy.deepcopy(change.get("type"))
            relation = compare_types(old_type, new_type)
            change["old_type"], change["relation"] = old_type, relation
            if new_type:
                columns[column] = new_type
            changes.append({"column": column, "relation": relation, "old": old_type, "new": new_type})
        if changes:
            stmt.attrs["type_changes"] = changes
            stmt.attrs["type_change"] = "narrowing" if any(
                c["relation"] == "narrowing" for c in changes
            ) else ("incompatible" if any(
                c["relation"] == "incompatible" for c in changes
            ) else changes[0]["relation"])
        return bad
    def apply_file(self, statements: list[Any]) -> list[dict[str, Any]]:
        annotations: list[dict[str, Any]] = []
        for stmt in statements:
            _blank(stmt)
            if self._structural(stmt) or self._annotate_types(stmt):
                self.poisoned = True
            if "type_change" in stmt.attrs:
                annotations.append({"seq": stmt.seq,
                    "type_change": stmt.attrs.get("type_change"),
                    "changes": copy.deepcopy(stmt.attrs.get("type_changes", []))})
        return annotations
    def replay_file(self, statements: list[Any], annotations: list[dict[str, Any]]) -> None:
        by_seq = {item["seq"]: item for item in annotations}
        for stmt in statements:
            _blank(stmt)
            if self._structural(stmt):
                self.poisoned = True
            record = by_seq.get(stmt.seq)
            table = str(stmt.attrs.get("table") or "")
            columns = self.state.setdefault(table, {}) if table else {}
            changes: list[dict[str, Any]] = []
            for change in stmt.attrs.get("type_alterations", []):
                column = str(change.get("column") or "")
                saved = next((c for c in (record or {}).get("changes", [])
                              if c.get("column") == column), None)
                if record is None or saved is None:
                    self.poisoned = True
                    continue
                old_type, relation = copy.deepcopy(saved.get("old")), saved.get("relation")
                change["old_type"], change["relation"] = old_type, relation
                new_type = copy.deepcopy(change.get("type"))
                if new_type and table:
                    columns[column] = new_type
                changes.append({"column": column, "relation": relation,
                                "old": old_type, "new": new_type})
            if changes and record is not None:
                stmt.attrs["type_changes"] = changes
                stmt.attrs["type_change"] = record.get("type_change", changes[0]["relation"])
def ordered_file_groups(statements: list[Any]) -> list[tuple[tuple[Any, str], list[Any]]]:
    """按 (version,file_rel,seq) 全量顺序聚合 up/single 语句为有序文件组。"""
    groups: dict[tuple[Any, str], list[Any]] = {}
    for stmt in sorted((s for s in statements if s.direction in ("up", "single")), key=_order_key):
        groups.setdefault((stmt.version, stmt.file_rel), []).append(stmt)
    return sorted(groups.items(), key=lambda kv: (kv[0][0] if kv[0][0] is not None else 0, kv[0][1]))

def annotate_type_changes(statements: list[Any]) -> None:
    """无缓存全链推演入口，行为与增量检查点路径严格一致。"""
    engine = TypeStateEngine()
    for _key, group in ordered_file_groups(statements):
        engine.apply_file(group)
