"""确定性工具函数。"""
from __future__ import annotations
import fnmatch
import hashlib
import json
import os
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
SEVERITY_RANK = {"info": 1, "warning": 2, "blocker": 3}
SEVERITY_ORDER = ("blocker", "warning", "info")
FIXED_MTIME_PLACEHOLDER = "1970-01-01T00:00:00Z"

class QianshenError(Exception):
    """带退出码的受控错误。"""
    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code

def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def digest(value: Any) -> str:
    return sha256_text(canonical_json(value))

def truncate(value: str, limit: int = 180) -> str:
    text = re.sub(r"\s+", " ", value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"

def normalize_rel(value: str | Path) -> str:
    return str(value).replace("\\", "/").lstrip("./")

def path_matches(path: str, pattern: str) -> bool:
    """同时支持 fnmatch 和简单前缀目录匹配。"""
    path = normalize_rel(path)
    pattern = normalize_rel(pattern)
    return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(Path(path).name, pattern)

def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity, 0)

def finding_sort_key(finding: Any) -> tuple[Any, ...]:
    return (
        -severity_rank(finding.severity),
        finding.version if finding.version is not None else 0,
        finding.file,
        finding.line_start,
        finding.rule_id,
        finding.fingerprint,
    )

def worse_severity(left: str, right: str) -> str:
    return left if severity_rank(left) >= severity_rank(right) else right

def downgrade_severity(severity: str) -> str:
    if severity == "blocker":
        return "warning"
    if severity == "warning":
        return "info"
    return severity

def parse_iso_datetime(value: str) -> datetime:
    text = (value or "").strip()
    if not text:
        raise ValueError("时钟字段为空")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

def parse_iso_date(value: str) -> date:
    return date.fromisoformat((value or "").strip())

def atomic_write_text(path: Path, content: str) -> None:
    ensure_dir(path.parent)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(content, encoding="utf-8", newline="\n")
    os.replace(temp, path)

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def relative_display(path: Path, base: Path | None = None) -> str:
    """优先返回相对路径，避免把用户绝对目录写入报告。"""
    base = base or Path.cwd()
    try:
        return normalize_rel(path.resolve().relative_to(base.resolve()))
    except ValueError:
        return path.name

def stable_fingerprint(parts: list[str], prefix: str = "qf-") -> str:
    return prefix + sha256_text("\x1f".join(parts))[:16]
