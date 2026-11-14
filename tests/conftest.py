from __future__ import annotations
import json
from pathlib import Path
import yaml
from qianshen.audit import run_audit
from qianshen.config import load_config
from qianshen.models import AuditOutcome
ROOT = Path(__file__).resolve().parents[1]
BASE_RULES = ROOT / "rules" / "default.yml"

def write_files(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

def make_config(
    tmp_path: Path,
    files: dict[str, str] | None = None,
    *,
    tag: str = "run",
    rules_text: str | None = None,
    exemptions_text: str | None = None,
    baseline_text: str | None = None,
    migrations_name: str = "migrations",
    **overrides,
) -> Path:
    if files is not None:
        write_files(tmp_path / migrations_name, files)
    rules_path = BASE_RULES
    if rules_text is not None:
        rules_path = tmp_path / f"rules_{tag}.yml"
        rules_path.write_text(rules_text, encoding="utf-8")
    config = {
        "project": "qianshen-audit",
        "version": 1,
        "migrations_dir": str(tmp_path / migrations_name),
        "dialect": "postgres",
        "naming": {"mode": "auto", "version_width": 4},
        "ignore": {"dirs": ["ignored_dir"], "globs": ["*.tmp.sql"], "paths": []},
        "rules_file": str(rules_path),
        "exemptions_file": None,
        "baseline_file": None,
        "output_dir": str(tmp_path / f"out_{tag}"),
        "ledger_path": str(tmp_path / f"ledger_{tag}.sqlite3"),
        "fail_on": "blocker",
        "clock": "2026-01-01T00:00:00Z",
        "large_tables": ["demo_events"],
        "permissions": {"allow_grants": False},
        "pairing": {"check_rollback": True},
        "irreversible_approvals": [],
        "rule_overrides": {},
    }
    if exemptions_text is not None:
        path = tmp_path / f"exemptions_{tag}.yml"
        path.write_text(exemptions_text, encoding="utf-8")
        config["exemptions_file"] = str(path)
    if baseline_text is not None:
        path = tmp_path / f"baseline_{tag}.yml"
        path.write_text(baseline_text, encoding="utf-8")
        config["baseline_file"] = str(path)
    config.update(overrides)
    path = tmp_path / f"qianshen_{tag}.yml"
    path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return path

def run_case(
    tmp_path: Path,
    files: dict[str, str] | None = None,
    *,
    tag: str = "run",
    **kwargs,
) -> tuple[AuditOutcome, Path, Path]:
    config_path = make_config(tmp_path, files, tag=tag, **kwargs)
    config = load_config(config_path)
    outcome = run_audit(config)
    return outcome, config.output_dir, config.ledger_path

def finding_ids(outcome: AuditOutcome) -> set[str]:
    return {finding.rule_id for finding in outcome.active_findings}

def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
PAIR = {
    "0001_base.up.sql": "CREATE TABLE IF NOT EXISTS demo_base (id INTEGER PRIMARY KEY);\n",
    "0001_base.down.sql": "DROP TABLE IF EXISTS demo_base;\n",
}
