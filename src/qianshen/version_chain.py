"""版本链、命名、清单指纹与基线核验；不依赖 SQL 解析。"""
from __future__ import annotations
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
import yaml
from .config import Config
from .discovery import detect_layout
from .models import FileInfo, Finding, make_finding
from .util import QianshenError, canonical_json, sha256_text
VALID_SEVERITIES = ("blocker", "warning", "info")

def _pad(version: int, width: int) -> str:
    return f"{version:0{width}d}"

def _vf(rule_id, title, severity, category, rel_path, version, direction, evidence,
        suggestion, file: FileInfo | None = None) -> Finding:
    return make_finding(
        rule_id=rule_id, title=title, severity=severity, category=category, file=rel_path,
        version=version, direction=direction, object_name=rel_path, evidence=evidence,
        suggestion=suggestion, source="version",
    )

def _baseline_severity(config: Config, key: str, default: str) -> str:
    baseline = config.raw.get("baseline") or {}
    if not isinstance(baseline, dict): raise QianshenError("baseline 配置必须是映射")
    value = str(baseline.get(key, default))
    if value not in VALID_SEVERITIES: raise QianshenError(f"baseline.{key} 必须是 blocker/warning/info")
    return value

def _load_baseline(path: Path) -> dict[str, dict[str, Any]]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise QianshenError(f"基线文件读取失败: {exc}") from exc
    records = data.get("files") if isinstance(data, dict) else data
    if not isinstance(records, list): raise QianshenError("基线文件必须包含 files 列表")
    result: dict[str, dict[str, Any]] = {}
    for item in records:
        if not isinstance(item, dict) or not item.get("path") or not item.get("sha256"):
            raise QianshenError("基线文件记录必须包含 path 与 sha256")
        result[str(item["path"]).replace("\\", "/")] = item
    return result

# 各版本/布局规则的固定文案，按 rule_id 集中声明，避免重复的多行调用。
_NAME_HINT = "使用 NNNN_description.up.sql、NNNN_description.down.sql 或 NNNN_description.sql。"

def _baseline_findings(files: list[FileInfo], config: Config):
    if config.baseline_file is None: return [], {"enabled": False}
    baseline = _load_baseline(config.baseline_file)
    current = {f.rel_path: f for f in files}
    modified = sorted(p for p in set(current) & set(baseline)
                      if current[p].sha256 != str(baseline[p]["sha256"]))
    deleted, added = sorted(set(baseline) - set(current)), sorted(set(current) - set(baseline))
    findings: list[Finding] = []
    for rel in modified:
        f = current[rel]
        findings.append(_vf("baseline.file_modified", "基线中的迁移文件被修改",
            _baseline_severity(config, "severity_modified", "blocker"), "baseline",
            rel, f.version, f.direction, f"{rel} sha256 与基线不一致",
            "确认这是授权变更，并更新基线；不要在评审前静默修改历史迁移。", f))
    for rel in deleted:
        item = baseline[rel]
        findings.append(_vf("baseline.file_deleted", "基线中的迁移文件被删除",
            _baseline_severity(config, "severity_deleted", "blocker"), "baseline",
            rel, item.get("version"), str(item.get("direction", "unknown")),
            f"{rel} 在输入目录中缺失", "恢复文件，或在评审记录中明确记录删除决定并更新基线。"))
    for rel in added:
        f = current[rel]
        findings.append(_vf("baseline.file_added", "检测到基线之外的新迁移文件",
            _baseline_severity(config, "severity_added", "warning"), "baseline",
            rel, f.version, f.direction, f"{rel} 不在基线清单中",
            "按正常评审流程检查新增迁移；新增文件默认不直接阻断。", f))
    return findings, {
        "enabled": True, "baseline_file": config.baseline_file.name,
        "counts": {"modified": len(modified), "deleted": len(deleted), "added": len(added)},
    }

def given_versions(files: list[FileInfo]) -> list[int]:
    return sorted({f.version for f in files if f.version is not None})

def build_input_summary(files: list[FileInfo], config: Config) -> dict[str, Any]:
    layout = detect_layout(files)
    fingerprints = [
        {"path": f.rel_path, "version": f.version, "direction": f.direction, "sha256": f.sha256}
        for f in sorted(files, key=lambda x: (x.version or 0, x.direction, x.rel_path))
    ]
    versions = given_versions(files)
    return {
        "root": config.migrations_dir.name, "files_total": len(files),
        "by_direction": dict(sorted(Counter(f.direction for f in files).items())),
        "versions": versions, "version_range": [versions[0], versions[-1]] if versions else None,
        "layout": layout["mode"], "sha256": sha256_text(canonical_json(fingerprints)),
        "files": fingerprints,
    }

def check_version_chain(files: list[FileInfo], config: Config):
    findings: list[Finding] = []
    layout = detect_layout(files)
    width = config.version_width
    named = [f for f in files if f.version is not None]
    for f in files:
        if f.direction == "unknown":
            findings.append(_vf("version.invalid_name", "迁移文件命名不符合模式", "blocker",
                "naming", f.rel_path, None, "unknown",
                f"{f.rel_path} 无法识别版本号或方向", _NAME_HINT, f))
        elif f.naming_error and f.naming_error.startswith("version_width"):
            findings.append(_vf("version.naming_width", "版本号宽度与配置不一致", "warning",
                "naming", f.rel_path, f.version, f.direction,
                f"{f.rel_path} 命名异常: {f.naming_error}",
                f"按配置使用 {width} 位零填充版本号，保证字典序与版本顺序一致。", f))
    paired = [f for f in files if f.direction in ("up", "down")]
    single = [f for f in files if f.direction == "single"]
    actual_mode = layout["mode"]
    if actual_mode == "mixed" or (config.naming_mode == "paired" and single) or (
        config.naming_mode == "single" and paired
    ):
        findings.append(_vf("version.mixed_layout", "同目录混用单文件与 up/down 成对模式",
            "blocker", "layout", ".", None, "mixed", "检测到单文件与成对文件共存",
            "一个迁移目录只使用一种布局；拆分目录或在配置中修正 naming.mode。"))
    if not files:
        findings.append(_vf("version.empty_input", "迁移目录中没有可评审的 SQL 文件",
            "blocker", "layout", ".", None, "unknown", "未发现 *.sql 文件",
            "检查 migrations_dir、忽略规则与文件名后缀。"))
    groups: dict[tuple[int, str], list[FileInfo]] = defaultdict(list)
    for f in named:
        groups[(f.version or 0, f.direction)].append(f)
    for (version, direction), group in sorted(groups.items()):
        if len(group) > 1:
            paths = ", ".join(sorted(f.rel_path for f in group))
            findings.append(_vf("version.duplicate", "同一版本与方向存在多个文件", "blocker",
                "version_chain", group[0].rel_path, version, direction,
                f"版本 {_pad(version, width)} {direction} 重复: {paths}",
                "移除重复文件，或为每个变更分配唯一递增版本号。", group[0]))
    versions = given_versions(files)
    missing: list[str] = []
    if versions:
        expected = 1
        for version in versions:
            if version > expected: missing.append(f"{_pad(expected, width)}-{_pad(version - 1, width)}")
            expected = max(expected, version + 1)
        if missing:
            anchor = named[0] if named else None
            findings.append(_vf("version.gap", "版本号存在缺口", "warning", "version_chain",
                anchor.rel_path if anchor else ".", versions[-1], "mixed",
                f"缺失版本区间: {', '.join(missing[:8])}",
                "确认缺失版本是否属于未交付变更；若使用基线分支，请记录说明。", anchor))
    ordered = sorted(named, key=lambda f: f.rel_path)
    if [f.version or 0 for f in ordered] != sorted(f.version or 0 for f in ordered):
        anchor = ordered[0] if ordered else None
        findings.append(_vf("version.out_of_order", "版本号字典序与数值顺序不一致", "warning",
            "version_chain", anchor.rel_path if anchor else ".", None, "mixed",
            "文件名字典序与数值版本序不同，建议统一版本号宽度",
            "统一零填充宽度，避免不同工具按文件名排序时出现乱序。", anchor))
    by_version: dict[int, set[str]] = defaultdict(set)
    for f in paired:
        if f.version is not None: by_version[f.version].add(f.direction)
    for version, directions in sorted(by_version.items()):
        for miss in sorted({"up", "down"} - directions):
            severity = "blocker" if miss == "up" else "warning"
            findings.append(_vf(f"version.missing_direction", f"版本缺少 {miss} 文件", severity,
                "version_chain", ".", version, miss,
                f"版本 {_pad(version, width)} 缺少 {miss} 文件",
                "补齐对应方向文件，或确认该版本不应存在成对迁移。"))
    input_summary = build_input_summary(files, config)
    baseline_findings, baseline_summary = _baseline_findings(files, config)
    findings.extend(baseline_findings)
    result = {
        "layout": actual_mode, "configured_mode": config.naming_mode, "versions": versions,
        "expected": [
            {"version": v, "directions": sorted({f.direction for f in named if f.version == v})}
            for v in versions
        ],
        "drift": {
            "duplicates": sum(1 for g in groups.values() if len(g) > 1),
            "gaps": len(missing) if versions else 0,
        },
        "baseline": baseline_summary,
        "manifest_sha256": input_summary["sha256"], "manifest": input_summary["files"],
    }
    return findings, result
