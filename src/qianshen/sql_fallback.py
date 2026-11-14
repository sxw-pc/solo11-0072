"""解析失败时的保守 token 分类；结果置信度由规则引擎降级表达。"""
from __future__ import annotations
import re
from typing import Any
from .sql_split import strip_comments

def token_classify(sql: str) -> tuple[str, list[str], dict[str, Any]]:
    text = re.sub(r"\s+", " ", strip_comments(sql)).strip()
    upper = text.upper()
    attrs: dict[str, Any] = {}
    if re.match(r"^BEGIN\b", upper):
        return "begin", [], attrs
    if re.match(r"^COMMIT\b", upper):
        return "commit", [], attrs
    if re.match(r"^ROLLBACK\b", upper):
        return "rollback", [], attrs
    match = re.match(
        r"^CREATE\s+(?:OR\s+REPLACE\s+)?(?:UNIQUE\s+)?(TABLE|INDEX|VIEW|TYPE)\s+"
        r"(?:IF\s+NOT\s+EXISTS\s+)?([\w.\"]+)",
        upper,
    )
    if match:
        kind, name = match.group(1).lower(), match.group(2).strip('"').lower()
        attrs["if_not_exists"] = "IF NOT EXISTS" in upper
        if kind == "index":
            target = re.search(r"\bON\s+([\w.\"]+)", upper)
            attrs["index"] = name
            attrs["table"] = target.group(1).strip('"').lower() if target else ""
            return "create_index", [name] + ([attrs["table"]] if attrs["table"] else []), attrs
        attrs["table"] = name
        return f"create_{kind}", [name], attrs
    match = re.match(r"^ALTER\s+TABLE\s+([\w.\"]+)\s+(.*)$", upper)
    if match:
        table, rest = match.group(1).strip('"').lower(), match.group(2)
        attrs.update({"table": table, "actions": ["other"]})
        if re.search(r"\bDROP\s+COLUMN\b", rest):
            attrs["actions"] = ["drop_column"]
            return "alter_table_drop_column", [table], attrs
        if re.search(r"\bADD\s+COLUMN\b", rest):
            attrs["actions"] = ["add_column"]
            attrs["has_if_not_exists"] = "IF NOT EXISTS" in rest
            attrs["added_columns"] = [
                {
                    "name": "",
                    "type": None,
                    "not_null": "NOT NULL" in rest,
                    "has_default": "DEFAULT" in rest,
                }
            ]
            return "alter_table_add_column", [table], attrs
        if re.search(r"\bALTER\s+COLUMN\b.*\bTYPE\b", rest):
            attrs["actions"] = ["alter_type"]
            return "alter_table_alter_type", [table], attrs
        return "alter_table", [table], attrs
    match = re.match(r"^DROP\s+(TABLE|INDEX|VIEW)\s+(?:IF\s+EXISTS\s+)?([\w.\"]+)", upper)
    if match:
        attrs["if_exists"] = "IF EXISTS" in upper
        return f"drop_{match.group(1).lower()}", [match.group(2).strip('"').lower()], attrs
    match = re.match(r"^TRUNCATE\s+(?:TABLE\s+)?([\w.\"]+)", upper)
    if match:
        name = match.group(1).strip('"').lower()
        return "truncate", [name], {"table": name}
    match = re.match(r"^UPDATE\s+([\w.\"]+)", upper)
    if match:
        table = match.group(1).strip('"').lower()
        return "update", [table], {"table": table, "has_where": bool(re.search(r"\bWHERE\b", upper))}
    match = re.match(r"^DELETE\s+FROM\s+([\w.\"]+)", upper)
    if match:
        table = match.group(1).strip('"').lower()
        return "delete", [table], {"table": table, "has_where": bool(re.search(r"\bWHERE\b", upper))}
    match = re.match(r"^INSERT\s+INTO\s+([\w.\"]+)", upper)
    if match:
        table = match.group(1).strip('"').lower()
        return "insert", [table], {"table": table, "insert_columns": [], "literal_values": 0}
    match = re.match(r"^(GRANT|REVOKE)\b", upper)
    if match:
        return match.group(1).lower(), [], {}
    return "other", [], attrs
