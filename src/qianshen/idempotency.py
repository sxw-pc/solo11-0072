"""工程可解释的幂等性评分；不是事务安全证明，也不生成修复 SQL。"""
from __future__ import annotations
import re
from collections import Counter, defaultdict
from typing import Any
from .models import FileInfo, StatementInfo

def _reason(code: str, delta: int, message: str) -> dict[str, Any]:
    return {"code": code, "delta": -abs(delta), "message": message}

def _score_file(file: FileInfo, statements: list[StatementInfo]) -> dict[str, Any]:
    modifying = [stmt for stmt in statements if stmt.is_ddl or stmt.is_dml]
    reasons: list[dict[str, Any]] = []
    if not modifying:
        return {
            "file": file.rel_path, "version": file.version, "direction": file.direction,
            "score": 100, "reasons": [],
        }
    has_begin = any(stmt.kind == "begin" for stmt in statements)
    has_end = any(stmt.kind in ("commit", "rollback") for stmt in statements)
    if len(modifying) > 1 and not (has_begin and has_end):
        reasons.append(_reason("no_transaction_boundary", 15,
                               f"{len(modifying)} 条变更语句未包裹在显式事务边界内"))
    repeated_objects: Counter[tuple[str, str]] = Counter()
    for stmt in statements:
        table = str(stmt.attrs.get("table") or "")
        if stmt.kind == "create_table" and not stmt.attrs.get("if_not_exists"):
            reasons.append(_reason("create_without_if_not_exists", 5, f"CREATE TABLE 未声明 IF NOT EXISTS: {table}"))
        if stmt.kind == "create_index" and not stmt.attrs.get("if_not_exists"):
            reasons.append(_reason("index_without_if_not_exists", 5, "CREATE INDEX 未声明 IF NOT EXISTS"))
        if "add_column" in stmt.actions and not stmt.attrs.get("has_if_not_exists", False):
            reasons.append(_reason("add_column_without_if_not_exists", 5, f"ADD COLUMN 未声明 IF NOT EXISTS: {table}"))
        if stmt.kind in ("drop_table", "drop_index", "drop_view") and not stmt.attrs.get("if_exists", False):
            reasons.append(_reason("drop_without_if_exists", 5, f"{stmt.kind.upper()} 未声明 IF EXISTS: {table}"))
        if stmt.kind in ("drop_table", "truncate", "alter_table_drop_column"):
            reasons.append(_reason("destructive_ddl", 10, f"包含破坏性语句: {stmt.kind}"))
        columns = {str(item).lower() for item in stmt.attrs.get("insert_columns", [])}
        if stmt.kind == "insert" and "id" in columns and int(stmt.attrs.get("literal_values", 0)) >= len(columns):
            reasons.append(_reason("fixed_primary_key_insert", 10, f"固定主键 INSERT: {table}"))
        if stmt.kind in ("update", "delete") and not stmt.attrs.get("has_where", False):
            reasons.append(_reason("unconditional_dml", 15, f"无 WHERE 的 {stmt.kind.upper()}: {table}"))
        if stmt.kind == "update" and re.search(
            r"\bset\b[\s\S]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\1\s*[-+]", stmt.raw, re.IGNORECASE,
        ):
            reasons.append(_reason("accumulating_update", 8, f"累计更新可能被重复应用: {table}"))
        if stmt.kind in ("create_table", "create_view", "create_type") and table:
            repeated_objects[(stmt.kind, table)] += 1
        elif stmt.kind == "create_index" and stmt.attrs.get("index"):
            repeated_objects[("create_index", str(stmt.attrs["index"]))] += 1
        for column in stmt.attrs.get("added_columns", []):
            if column.get("name"):
                repeated_objects[("add_column", f"{table}.{column['name']}")] += 1
    for kind, name in sorted(k for k, c in repeated_objects.items() if c > 1):
        reasons.append(_reason("duplicate_object", 10, f"同一文件重复定义对象: {kind}:{name}"))
    total_deduction = sum(abs(item["delta"]) for item in reasons)
    reasons.sort(key=lambda item: (item["code"], item["message"]))
    return {
        "file": file.rel_path, "version": file.version, "direction": file.direction,
        "score": max(0, 100 - total_deduction), "reasons": reasons,
    }

def calculate_idempotency(
    files: list[FileInfo], statements: list[StatementInfo]
) -> dict[str, Any]:
    by_file: dict[str, list[StatementInfo]] = defaultdict(list)
    for stmt in statements:
        by_file[stmt.file_rel].append(stmt)
    file_results = [
        _score_file(file, sorted(by_file.get(file.rel_path, []), key=lambda item: item.seq))
        for file in sorted(files, key=lambda item: item.rel_path)
    ]
    scored = [item for item in file_results if item["reasons"] or item["score"] < 100]
    if not file_results:
        score = 100
    elif scored:
        score = round(sum(item["score"] for item in scored) / len(scored))
    else:
        score = 100
    reason_counts = Counter(r["code"] for item in file_results for r in item["reasons"])
    return {
        "score": max(0, min(100, score)),
        "method": "100 分起扣，按文件取平均；扣分项见下，不代表事务安全证明",
        "files": file_results,
        "reason_counts": dict(sorted(reason_counts.items())),
        "low_score_files": [
            {"file": item["file"], "score": item["score"]}
            for item in file_results if item["score"] < 70
        ],
    }
