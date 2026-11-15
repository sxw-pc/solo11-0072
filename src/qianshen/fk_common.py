"""外键顺序审查的共享数据结构与无状态辅助函数。"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from .models import Finding, StatementInfo, make_finding
from .util import severity_for_source

ORDER_RULE = "rollback.foreign_key_order"
UNCONFIRMED_RULE = "rollback.foreign_key_unconfirmed"


@dataclass
class EdgeState:
    """一条外键边在顺序模拟中的生命周期状态。"""

    constraint: str
    source_table: str
    referenced_table: str
    defined: tuple[str, int] = ("", 0)
    live: bool = True

    def key(self) -> tuple[str, str]:
        return self.source_table, self.constraint

    def to_dict(self) -> dict[str, Any]:
        return {
            "constraint": self.constraint, "source_table": self.source_table,
            "referenced_table": self.referenced_table, "defined_file": self.defined[0],
            "defined_seq": self.defined[1], "live": self.live,
        }


@dataclass
class PairFkResult:
    version: int
    status: str = "ok"
    edges: list[dict[str, Any]] = field(default_factory=list)
    unconfirmed: list[dict[str, Any]] = field(default_factory=list)
    order_findings: list[str] = field(default_factory=list)
    unconfirmed_findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version, "status": self.status, "edges": self.edges,
            "unconfirmed": self.unconfirmed, "order_findings": self.order_findings,
            "unconfirmed_findings": self.unconfirmed_findings,
        }


def make_order_finding(
    rule_id: str, title: str, severity: str, stmt: StatementInfo | None,
    version: int, direction: str, object_name: str, evidence: str,
    suggestion: str, detail: str, fallback_file: str = "",
) -> Finding:
    source = "token" if stmt is not None and not stmt.parse_ok else "ast"
    effective, confidence = severity_for_source(source, severity)
    return make_finding(
        rule_id=rule_id, title=title, severity=effective, category="rollback",
        file=stmt.file_rel if stmt else fallback_file, version=version,
        direction=direction, object_name=object_name, evidence=evidence,
        suggestion=suggestion, source=source,
        line_start=stmt.start_line if stmt else 1, line_end=stmt.end_line if stmt else 1,
        statement_seq=stmt.seq if stmt else None, confidence=confidence, detail=detail,
    )


def stmt_table(stmt: StatementInfo) -> str:
    return str(stmt.attrs.get("table") or (stmt.objects[0] if stmt.objects else ""))


def drop_tables(stmt: StatementInfo) -> list[str]:
    if stmt.kind != "drop_table":
        return []
    if stmt.parse_ok and stmt.objects:
        return list(stmt.objects)
    table = stmt_table(stmt)
    return [table] if table else []


def edges_to(edges: dict[tuple[str, str], EdgeState], table: str) -> list[EdgeState]:
    """以 table 为被引用（父）表的存活跨表外键边（自引用不构成顺序问题）。"""
    return sorted(
        (
            e for e in edges.values()
            if e.live and e.referenced_table == table and e.source_table != table
        ),
        key=lambda e: e.key(),
    )


def edges_from(edges: dict[tuple[str, str], EdgeState], table: str) -> list[EdgeState]:
    """以 table 为源（子）表的存活外键边。"""
    return sorted(
        (e for e in edges.values() if e.live and e.source_table == table),
        key=lambda e: e.key(),
    )


def unconfirmed(stmt: StatementInfo | None, object_name: str, reason: str) -> dict[str, Any]:
    return {
        "file": stmt.file_rel if stmt else "", "statement_seq": stmt.seq if stmt else None,
        "line": stmt.start_line if stmt else 1, "object": object_name, "reason": reason,
    }


def dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    result = []
    for item in items:
        marker = (item["file"], item["statement_seq"], item["object"], item["reason"])
        if marker not in seen:
            seen.add(marker)
            result.append(item)
    return sorted(result, key=lambda item: (item["file"], item["line"] or 0, item["object"]))


def rename_note(
    stmt: StatementInfo, table: str, edges: dict[tuple[str, str], EdgeState],
) -> dict[str, Any]:
    new_names = stmt.attrs.get("renamed_tables") or []
    involved = {name for name in (table, *new_names) if name}
    touched = [
        e for e in edges.values()
        if e.source_table in involved or e.referenced_table in involved
    ]
    if touched:
        names = ", ".join(
            f"{e.source_table}.{e.constraint}->{e.referenced_table}" for e in touched[:4]
        )
        reason = f"表改名涉及 {sorted(involved)}，外键边 {names} 的后续归属无法确认"
    else:
        reason = f"表改名 {table} -> {new_names}，改名后名称与外键引用的对应关系无法确认"
    return unconfirmed(stmt, table or (new_names[0] if new_names else ""), reason)


def register_edges(
    stmt: StatementInfo, table: str, file_rel: str,
    edges: dict[tuple[str, str], EdgeState],
) -> list[EdgeState]:
    created = [
        EdgeState(item["constraint"], table, item["referenced_table"], (file_rel, stmt.seq))
        for item in stmt.attrs.get("foreign_keys", [])
    ]
    for edge in created:
        edges[edge.key()] = edge
    return created


def retire(edges: dict[tuple[str, str], EdgeState], table: str) -> None:
    for edge in edges_from(edges, table) + edges_to(edges, table):
        edge.live = False
