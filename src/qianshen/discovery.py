"""迁移目录发现：只做文件层扫描，不解析 SQL。"""
from __future__ import annotations
import os
import re
from pathlib import Path
from .config import Config
from .models import FileInfo
from .util import (
    FIXED_MTIME_PLACEHOLDER,
    QianshenError,
    normalize_rel,
    path_matches,
    sha256_bytes,
)
PAIRED_RE = re.compile(
    r"^(?P<version>\d{1,8})_(?P<description>[A-Za-z0-9][A-Za-z0-9_-]*)\."
    r"(?P<direction>up|down)\.sql$"
)
SINGLE_RE = re.compile(
    r"^(?P<version>\d{1,8})_(?P<description>[A-Za-z0-9][A-Za-z0-9_-]*)\.sql$"
)

def _ignored(rel_path: str, overrides: set[str], config: Config) -> bool:
    rel = normalize_rel(rel_path)
    parts = rel.split("/")
    if any(part in set(config.ignore.dirs) for part in parts[:-1]):
        return True
    if rel in overrides:
        return True
    if any(rel == item or rel.startswith(item.rstrip("/") + "/") for item in config.ignore.paths):
        return True
    return any(path_matches(rel, pattern) for pattern in config.ignore.globs)

def _parse_name(name: str, config: Config) -> tuple[int | None, str, str, str | None]:
    match = PAIRED_RE.match(name) or SINGLE_RE.match(name)
    if not match:
        return None, "", "unknown", "filename_does_not_match_supported_patterns"
    version_raw = match.group("version")
    error = (None if len(version_raw) == config.version_width
             else f"version_width:{len(version_raw)}!=expected:{config.version_width}")
    direction = match.groupdict().get("direction") or "single"
    return int(version_raw), match.group("description"), direction, error

def _line_count(text: str) -> int:
    if not text:
        return 0
    return len(text.splitlines())

def discover(config: Config) -> tuple[list[FileInfo], list[dict[str, object]]]:
    root = config.migrations_dir
    if not root.exists() or not root.is_dir():
        raise QianshenError(f"迁移目录不存在或不是目录: {root.name}")
    overrides = {normalize_rel(item) for item in config.ignore.paths}
    files: list[FileInfo] = []
    errors: list[dict[str, object]] = []
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirnames[:] = sorted(
            name for name in dirnames if name not in set(config.ignore.dirs)
        )
        for filename in sorted(filenames):
            if Path(filename).suffix.lower() != ".sql":
                continue
            path = current_path / filename
            try:
                rel_path = normalize_rel(path.relative_to(root))
            except ValueError:
                rel_path = filename
            if _ignored(rel_path, overrides, config):
                continue
            try:
                data = path.read_bytes()
            except OSError as exc:
                errors.append({"stage": "discovery", "file": rel_path, "line": 0,
                               "code": "read_error", "message": str(exc)[:180]})
                data = b""
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                errors.append({"stage": "discovery", "file": rel_path, "line": 0,
                               "code": "decode_error",
                               "message": f"UTF-8 解码失败: {exc.reason}"})
                text = ""
            version, description, direction, naming_error = _parse_name(filename, config)
            read_error = next((item["message"] for item in errors if item["file"] == rel_path), None)
            files.append(FileInfo(
                path=path, rel_path=rel_path, version=version,
                version_raw=str(version) if version is not None else None,
                description=description, direction=direction, size_bytes=len(data),
                line_count=_line_count(text), sha256=sha256_bytes(data),
                mtime_placeholder=FIXED_MTIME_PLACEHOLDER,
                naming_error=naming_error, text=text, read_error=read_error))
    files.sort(key=lambda item: item.rel_path)
    return files, errors

def detect_layout(files: list[FileInfo]) -> dict[str, object]:
    paired = [f for f in files if f.direction in ("up", "down")]
    single = [f for f in files if f.direction == "single"]
    unknown = [f for f in files if f.direction == "unknown"]
    mode = ("mixed" if paired and single else "paired" if paired
            else "single" if single else "unknown")
    return {"mode": mode, "paired_files": len(paired), "single_files": len(single),
            "unknown_files": len(unknown),
            "versions": sorted({f.version for f in files if f.version is not None})}
