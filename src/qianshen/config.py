"""主配置加载与校验。配置错误统一抛出退出码 2 的受控错误。"""
from __future__ import annotations
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
import yaml
from .util import QianshenError, canonical_json, parse_iso_datetime, sha256_text
ALLOWED_DIALECTS = ("postgres", "mysql", "sqlite")
ALLOWED_FAIL_ON = ("blocker", "warning", "info", "none")
ALLOWED_MODES = ("auto", "paired", "single")
DEFAULT_CLOCK = "2026-01-01T00:00:00Z"
@dataclass
class IgnoreConfig:
    dirs: list[str] = field(default_factory=list)
    globs: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
@dataclass
class Config:
    path: Path
    base_dir: Path
    project: str
    migrations_dir: Path
    dialect: str
    naming_mode: str
    version_width: int
    ignore: IgnoreConfig
    rules_file: Path
    exemptions_file: Path | None
    baseline_file: Path | None
    output_dir: Path
    ledger_path: Path
    fail_on: str
    clock: str
    large_tables: list[str]
    allow_grants: bool
    irreversible_approvals: list[str]
    rule_overrides: dict[str, dict[str, Any]]
    raw: dict[str, Any] = field(repr=False)
    @property
    def config_digest(self) -> str:
        stable = dict(self.raw)
        stable["_dialect"] = self.dialect
        stable["_fail_on"] = self.fail_on
        stable["_clock"] = self.clock
        return sha256_text(canonical_json(stable))
    def summary(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "dialect": self.dialect,
            "naming_mode": self.naming_mode,
            "version_width": self.version_width,
            "fail_on": self.fail_on,
            "clock": self.clock,
            "ignore": {
                "dirs": list(self.ignore.dirs),
                "globs": list(self.ignore.globs),
                "paths": list(self.ignore.paths),
            },
            "allow_grants": self.allow_grants,
            "large_tables": list(self.large_tables),
            "rule_overrides": dict(self.rule_overrides),
            "has_baseline": self.baseline_file is not None,
            "has_exemptions": self.exemptions_file is not None,
        }

def _as_dict(value: Any, name: str) -> dict[str, Any]:
    if value is None: return {}
    if not isinstance(value, dict): raise QianshenError(f"配置字段 {name} 必须是映射")
    return value
def _as_str_list(value: Any, name: str) -> list[str]:
    if value is None: return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise QianshenError(f"配置字段 {name} 必须是字符串列表")
    return list(value)

def _resolve(value: Any, base: Path, name: str) -> Path:
    if not isinstance(value, str) or not value.strip(): raise QianshenError(f"配置字段 {name} 必须是非空路径")
    candidate = Path(value).expanduser()
    if not candidate.is_absolute(): candidate = base / candidate
    return candidate.resolve()

def _as_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool): raise QianshenError(f"配置字段 {name} 必须是布尔值")
    return value
def _validate_clock(value: Any) -> str:
    if value is None: return DEFAULT_CLOCK
    if not isinstance(value, str): raise QianshenError("配置字段 clock 必须是 ISO 8601 字符串")
    try:
        parse_iso_datetime(value)
    except ValueError as exc:
        raise QianshenError(f"配置字段 clock 无效: {exc}") from exc
    return value

def _validate_overrides(value: Any) -> dict[str, dict[str, Any]]:
    data = _as_dict(value, "rule_overrides")
    result: dict[str, dict[str, Any]] = {}
    for rule_id, item in data.items():
        if not isinstance(rule_id, str) or not isinstance(item, dict):
            raise QianshenError("rule_overrides 必须是 {规则ID: {severity/enabled}}")
        entry: dict[str, Any] = {}
        if "severity" in item:
            if item["severity"] not in ("blocker", "warning", "info"): raise QianshenError(f"规则 {rule_id} 的严重级别无效")
            entry["severity"] = item["severity"]
        if "enabled" in item:
            if not isinstance(item["enabled"], bool): raise QianshenError(f"规则 {rule_id} 的 enabled 必须是布尔值")
            entry["enabled"] = item["enabled"]
        result[rule_id] = entry
    return result

def load_config(
    path: str | Path,
    *,
    migrations_override: str | Path | None = None,
    out_override: str | Path | None = None,
    ledger_override: str | Path | None = None,
    now_override: str | None = None,
) -> Config:
    config_path = Path(path).expanduser().resolve()
    if not config_path.is_file(): raise QianshenError(f"配置文件不存在: {path}")
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise QianshenError(f"配置读取失败: {exc}") from exc
    if not isinstance(raw, dict): raise QianshenError("配置文件根节点必须是映射")
    base = config_path.parent
    try:
        dialect = str(raw.get("dialect", "postgres")).lower()
        if dialect not in ALLOWED_DIALECTS: raise QianshenError(f"dialect 必须是 {', '.join(ALLOWED_DIALECTS)}")
        naming = _as_dict(raw.get("naming"), "naming")
        mode = str(naming.get("mode", "auto")).lower()
        if mode not in ALLOWED_MODES: raise QianshenError(f"naming.mode 必须是 {', '.join(ALLOWED_MODES)}")
        width = naming.get("version_width", 4)
        if not isinstance(width, int) or width < 1 or width > 8:
            raise QianshenError("naming.version_width 必须是 1-8 的整数")
        ignore_raw = _as_dict(raw.get("ignore"), "ignore")
        permissions = _as_dict(raw.get("permissions"), "permissions")
        fail_on = str(raw.get("fail_on", "blocker")).lower()
        if fail_on not in ALLOWED_FAIL_ON: raise QianshenError(f"fail_on 必须是 {', '.join(ALLOWED_FAIL_ON)}")
        config = Config(
            path=config_path, base_dir=base,
            project=str(raw.get("project", "qianshen-audit")),
            migrations_dir=_resolve(raw.get("migrations_dir", "fixtures/migrations_risky"), base, "migrations_dir"),
            dialect=dialect, naming_mode=mode, version_width=width,
            ignore=IgnoreConfig(
                dirs=_as_str_list(ignore_raw.get("dirs"), "ignore.dirs"),
                globs=_as_str_list(ignore_raw.get("globs"), "ignore.globs"),
                paths=_as_str_list(ignore_raw.get("paths"), "ignore.paths")),
            rules_file=_resolve(raw.get("rules_file", "rules/default.yml"), base, "rules_file"),
            exemptions_file=_resolve(raw["exemptions_file"], base, "exemptions_file") if raw.get("exemptions_file") else None,
            baseline_file=_resolve(raw["baseline_file"], base, "baseline_file") if raw.get("baseline_file") else None,
            output_dir=_resolve(raw.get("output_dir", "out"), base, "output_dir"),
            ledger_path=_resolve(raw.get("ledger_path", ".qianshen/ledger.sqlite3"), base, "ledger_path"),
            fail_on=fail_on, clock=_validate_clock(now_override or raw.get("clock")),
            large_tables=_as_str_list(raw.get("large_tables"), "large_tables"),
            allow_grants=_as_bool(permissions.get("allow_grants", False), "permissions.allow_grants"),
            irreversible_approvals=_as_str_list(raw.get("irreversible_approvals"), "irreversible_approvals"),
            rule_overrides=_validate_overrides(raw.get("rule_overrides")), raw=raw,
        )
    except QianshenError:
        raise
    except (TypeError, ValueError) as exc:
        raise QianshenError(f"配置校验失败: {exc}") from exc
    if migrations_override is not None:
        config = replace(config, migrations_dir=Path(migrations_override).expanduser().resolve())
    if out_override is not None: config = replace(config, output_dir=Path(out_override).expanduser().resolve())
    if ledger_override is not None:
        config = replace(config, ledger_path=Path(ledger_override).expanduser().resolve())
    if now_override is not None: config = replace(config, clock=_validate_clock(now_override))
    if not config.rules_file.is_file(): raise QianshenError(f"规则文件不存在: {config.rules_file.name}")
    for label, path in (("豁免", config.exemptions_file), ("基线", config.baseline_file)):
        if path is not None and not path.is_file(): raise QianshenError(f"{label}文件不存在: {path.name}")
    return config
