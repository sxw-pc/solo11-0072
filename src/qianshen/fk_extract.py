"""从 sqlglot AST 中提取外键引用边（CREATE TABLE 与 ALTER TABLE 两种形态）。

提取结果是纯字典记录，保留约束名、源表、被引用表与定义形态，供语句顺序
审查使用；解析失败的语句不会进入这里，由 token 降级路径单独保守处理。
"""
from __future__ import annotations
from typing import Any
from sqlglot import exp


def _reference_table(reference: exp.Reference | None) -> str:
    """从 FOREIGN KEY ... REFERENCES 节点取被引用表名（去掉 schema/引号）。"""
    if reference is None:
        return ""
    target = reference.this
    if isinstance(target, exp.Schema):
        target = target.this
    return getattr(target, "name", "") or ""


def _fk_record(
    source_table: str, constraint_name: str, columns: list[str],
    referenced_table: str, defined_in: str,
) -> dict[str, Any]:
    name = constraint_name or (
        f"__anon_fk_{source_table}_{'_'.join(columns) or 'fkey'}_{referenced_table}"
    )
    return {
        "constraint": name, "named": bool(constraint_name), "source_table": source_table,
        "columns": sorted(columns), "referenced_table": referenced_table,
        "defined_in": defined_in,
    }


def _fk_columns(foreign_key: exp.ForeignKey) -> list[str]:
    return [col.name for col in foreign_key.expressions if getattr(col, "name", "")]


def extract_create_foreign_keys(ast: exp.Create, table: str) -> list[dict[str, Any]]:
    """提取 CREATE TABLE 内联 REFERENCES 与表级 FOREIGN KEY 约束。"""
    if not table or not isinstance(ast.this, exp.Schema):
        return []
    edges: list[dict[str, Any]] = []
    for item in ast.this.expressions:
        if isinstance(item, exp.ColumnDef):
            for constraint in item.args.get("constraints") or []:
                reference = constraint.args.get("kind")
                if isinstance(reference, exp.Reference):
                    edges.append(_fk_record(
                        table, "", [item.name],
                        _reference_table(reference), "inline_reference",
                    ))
        elif isinstance(item, exp.Constraint):
            for foreign_key in item.find_all(exp.ForeignKey):
                edges.append(_fk_record(
                    table, item.name, _fk_columns(foreign_key),
                    _reference_table(foreign_key.args.get("reference")), "table_constraint",
                ))
    return edges


def extract_alter_foreign_keys(
    ast: exp.Alter, table: str
) -> tuple[list[dict[str, Any]], list[str]]:
    """提取 ALTER TABLE ADD CONSTRAINT 外键；同时收集 DROP CONSTRAINT 名称。"""
    edges: list[dict[str, Any]] = []
    dropped: list[str] = []
    for action in ast.args.get("actions") or []:
        if isinstance(action, exp.AddConstraint):
            for constraint in action.expressions or []:
                if isinstance(constraint, exp.Constraint):
                    for foreign_key in constraint.find_all(exp.ForeignKey):
                        edges.append(_fk_record(
                            table, constraint.name, _fk_columns(foreign_key),
                            _reference_table(foreign_key.args.get("reference")),
                            "add_constraint",
                        ))
        elif isinstance(action, exp.Drop) and str(action.args.get("kind") or "").upper() == "CONSTRAINT":
            dropped.extend(
                target.name for target in action.args.get("tables") or []
                if getattr(target, "name", "")
            )
    return edges, dropped
