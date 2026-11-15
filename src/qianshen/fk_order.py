"""外键依赖的语句顺序审查（离线静态，不执行 SQL）。

按版本对核验外键引用边：up 中父表必须先于子表创建，down 中子表必须先于
父表删除。解析失败、表改名与同语句多动作只降低置信度并产出“未确认依赖”，
绝不把未知依赖宣称为已验证安全。

两遍扫描：版本升序模拟 up 累积外键生命周期，再按版本降序模拟 down（真实
回滚顺序）并共享边状态，因此后续版本已删除的外键不会永久阻断更早版本。
"""
from __future__ import annotations
from typing import Any
from .fk_common import (
    ORDER_RULE, UNCONFIRMED_RULE, EdgeState, PairFkResult, dedupe, drop_tables,
    edges_from, edges_to, make_order_finding as _finding, register_edges, rename_note,
    retire, stmt_table as _table, unconfirmed as _unconfirmed,
)
from .models import FileInfo, Finding, StatementInfo


def _check_up(
    version: int, up: FileInfo, statements: list[StatementInfo],
    edges: dict[tuple[str, str], EdgeState], known_tables: set[str],
) -> tuple[list[Finding], list[dict[str, Any]], list[EdgeState]]:
    """核验当前版本 up 的父表创建顺序，登记本版本产生/删除的外键边。

    ``known_tables`` 是此前版本已创建的表集合；父表在更早版本存在时不阻断，
    仅保守登记未确认项；父表在任何版本都不可见时才产生顺序阻断发现。
    """
    findings: list[Finding] = []
    notes: list[dict[str, Any]] = []
    created: list[EdgeState] = []
    created_tables: set[str] = set()

    for stmt in statements:
        table = _table(stmt)
        if stmt.kind == "create_table" and table:
            for edge in register_edges(stmt, table, up.rel_path, edges):
                if edge.referenced_table != table and edge.referenced_table not in created_tables:
                    if edge.referenced_table in known_tables:
                        notes.append(_unconfirmed(
                            stmt, edge.referenced_table,
                            f"外键 {edge.constraint}: {table} -> {edge.referenced_table} "
                            "的父表来自更早版本，本配对无法独立确认其创建顺序"))
                    else:
                        findings.append(_finding(
                            ORDER_RULE, "up 中外键依赖的父表未先于子表创建", "blocker",
                            stmt, version, "up", table,
                            f"外键 {edge.constraint}: {table} -> {edge.referenced_table}；"
                            f"子表创建于 {up.rel_path}:{stmt.start_line}，此前未见父表创建语句",
                            "调整 up 语句顺序，先创建被引用的父表，再创建带外键的子表。",
                            f"up-order:{table}->{edge.referenced_table}:{edge.constraint}",
                            fallback_file=up.rel_path,
                        ))
                created.append(edge)
            created_tables.add(table)
            known_tables.add(table)
        elif stmt.kind.startswith("alter_table"):
            for edge in register_edges(stmt, table, up.rel_path, edges):
                created.append(edge)
                if edge.referenced_table not in created_tables and edge.referenced_table not in known_tables:
                    findings.append(_finding(
                        ORDER_RULE, "up 中外键依赖的父表未先于约束创建", "blocker",
                        stmt, version, "up", table or edge.constraint,
                        f"外键 {edge.constraint}: {table} -> {edge.referenced_table}；"
                        f"约束添加于 {up.rel_path}:{stmt.start_line}，此前未见父表创建语句",
                        "确认父表已在更早版本创建，或先创建父表再添加外键约束。",
                        f"up-order:{table}->{edge.referenced_table}:{edge.constraint}",
                        fallback_file=up.rel_path,
                    ))
            for name in stmt.attrs.get("dropped_constraints", []):
                edge = edges.get((table, name))
                if edge is not None:
                    edge.live = False
                if stmt.attrs.get("multi_action"):
                    notes.append(_unconfirmed(
                        stmt, table or name,
                        f"同语句多动作包含 DROP CONSTRAINT {name}，外键生命周期无法逐条确认"))
            if "rename_table" in stmt.actions:
                notes.append(rename_note(stmt, table, edges))
        elif stmt.kind == "drop_table" and table and not stmt.parse_ok:
            notes.append(_unconfirmed(
                stmt, table, "DROP TABLE 来自解析降级，无法确认其外键依赖顺序"))
        if not stmt.parse_ok and _table(stmt):
            notes.append(_unconfirmed(
                stmt, _table(stmt),
                f"语句解析不完整（{stmt.parse_warning or 'parse fallback'}），外键依赖无法确认"))
    return findings, dedupe(notes), created


def _check_down(
    version: int, down: FileInfo, statements: list[StatementInfo],
    edges: dict[tuple[str, str], EdgeState],
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """模拟本版本 down，核验子表先于父表删除，就地更新共享边状态。"""
    findings: list[Finding] = []
    notes: list[dict[str, Any]] = []

    for stmt in statements:
        table = _table(stmt)
        if stmt.kind == "drop_table":
            targets = drop_tables(stmt)
            if not stmt.parse_ok:
                notes.append(_unconfirmed(
                    stmt, table or "unknown",
                    "DROP TABLE 来自解析降级，无法确认外键依赖的删除顺序"))
                for name in targets:
                    retire(edges, name)
                continue
            if len(targets) > 1:
                # 同语句多表删除无法区分先后：先就全部存活边保守登记，再统一退役
                for name in targets:
                    for edge in edges_to(edges, name) + edges_from(edges, name):
                        notes.append(_unconfirmed(
                            stmt, name,
                            "同语句删除多个表，无法确认外键父子表的删除先后："
                            f"{edge.source_table}.{edge.constraint}->{edge.referenced_table}"))
                for name in targets:
                    retire(edges, name)
                continue
            if stmt.attrs.get("multi_action"):
                notes.append(_unconfirmed(
                    stmt, table or "unknown",
                    "DROP TABLE 与其他动作位于同一语句，外键依赖顺序无法逐条确认"))
            name = targets[0] if targets else table
            for edge in edges_to(edges, name):
                findings.append(_finding(
                    ORDER_RULE, "down 中父表先于依赖它的子表删除，外键约束会失败", "blocker",
                    stmt, version, "down", name,
                    f"外键 {edge.constraint}: {edge.source_table} -> {edge.referenced_table}；"
                    f"父表 {name} 删除于 {down.rel_path}:{stmt.start_line}，"
                    f"子表 {edge.source_table} 尚未在本 down 中删除",
                    "调整 down 语句顺序，先 DROP 子表（或先 DROP 外键约束），再 DROP 父表。",
                    f"down-order:{edge.source_table}->{name}:{edge.constraint}",
                    fallback_file=down.rel_path,
                ))
            retire(edges, name)
        elif stmt.kind == "create_table" and table:
            register_edges(stmt, table, down.rel_path, edges)
        elif stmt.kind.startswith("alter_table"):
            register_edges(stmt, table, down.rel_path, edges)
            for name in stmt.attrs.get("dropped_constraints", []):
                edge = edges.get((table, name))
                if edge is not None:
                    edge.live = False
            if stmt.attrs.get("multi_action"):
                notes.append(_unconfirmed(
                    stmt, table,
                    "同语句多动作的 ALTER TABLE，外键约束增删与表依赖顺序无法逐条确认"))
            if "rename_table" in stmt.actions:
                notes.append(rename_note(stmt, table, edges))
        if not stmt.parse_ok and _table(stmt):
            notes.append(_unconfirmed(
                stmt, _table(stmt),
                f"语句解析不完整（{stmt.parse_warning or 'parse fallback'}），外键依赖无法确认"))
    return findings, dedupe(notes)


def check_foreign_key_order(
    up_files: dict[int, FileInfo], down_files: dict[int, FileInfo],
    by_file: dict[str, list[StatementInfo]],
) -> tuple[list[Finding], dict[int, PairFkResult]]:
    """按版本对构建外键生命周期并核验 up/down 语句顺序。"""
    findings: list[Finding] = []
    results: dict[int, PairFkResult] = {}
    edges: dict[tuple[str, str], EdgeState] = {}
    created_by_version: dict[int, list[EdgeState]] = {}
    notes_by_version: dict[int, list[dict[str, Any]]] = {}
    known_tables: set[str] = set()

    for version in sorted(up_files):  # 第一遍：升序模拟 up
        up = up_files[version]
        statements = sorted(by_file.get(up.rel_path, []), key=lambda s: s.seq)
        up_findings, notes, created = _check_up(
            version, up, statements, edges, known_tables,
        )
        findings.extend(up_findings)
        created_by_version[version] = created
        notes_by_version[version] = notes
        results[version] = PairFkResult(
            version, order_findings=[f.fingerprint for f in up_findings],
        )

    for version in sorted(up_files, reverse=True):  # 第二遍：降序模拟 down（真实回滚顺序）
        result = results[version]
        down = down_files.get(version)
        unique = {edge.key(): edge for edge in created_by_version.get(version, [])}
        result.edges = [
            edge.to_dict() for edge in sorted(
                unique.values(), key=lambda e: (e.source_table, e.constraint),
            )
        ]
        if down is not None:
            statements = sorted(by_file.get(down.rel_path, []), key=lambda s: s.seq)
            down_findings, notes = _check_down(version, down, statements, edges)
            findings.extend(down_findings)
            result.order_findings.extend(f.fingerprint for f in down_findings)
            result.unconfirmed = dedupe(notes_by_version.get(version, []) + notes)

    for version in sorted(results):  # 未确认依赖统一生成 warning（token 场景再降级）
        result = results[version]
        down = down_files.get(version)
        for item in result.unconfirmed:
            stmt = next(
                (s for s in by_file.get(item["file"], []) if s.seq == item["statement_seq"]), None)
            direction = "down" if down is not None and item["file"] == down.rel_path else "up"
            finding = _finding(
                UNCONFIRMED_RULE, "外键依赖顺序无法完整确认", "warning", stmt,
                version, direction, item["object"], item["reason"],
                "人工核对该语句涉及的外键父子表顺序，或将复合动作拆分为独立语句后重新评审。",
                f"fk-unconfirmed:{item['file']}:{item['statement_seq']}:{item['object']}",
                fallback_file=item["file"],
            )
            findings.append(finding)
            result.unconfirmed_findings.append(finding.fingerprint)
        if result.order_findings:
            result.status = "foreign_key_order"
        elif result.unconfirmed_findings:
            result.status = "foreign_key_unconfirmed"
    return findings, results
