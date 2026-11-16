"""确定性 JSON 报告。"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from . import TOOL_NAME, TOOL_TITLE, __version__
from .models import AuditOutcome
from .util import atomic_write_text, finding_sort_key
SCHEMA_VERSION = "1.0"

def sorted_active(outcome: AuditOutcome) -> list[Any]:
    return sorted(outcome.active_findings, key=finding_sort_key)

def build_report(outcome: AuditOutcome) -> dict[str, Any]:
    active = sorted_active(outcome)
    counts = outcome.severity_counts()
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "title": TOOL_TITLE, "version": __version__},
        "run": {"run_id": outcome.run_id, "started_at": outcome.started_at,
                "ended_at": outcome.ended_at, "dialect": outcome.dialect,
                "fail_on": outcome.fail_on, "conclusion": outcome.conclusion,
                "exit_code": outcome.exit_code,
                "reproduce_command": outcome.reproduce_command},
        "configuration": outcome.config_summary,
        "input": dict(outcome.input_summary, version_chain=outcome.version_result),
        "summary": {"files": len(outcome.files), "statements": len(outcome.statements),
            "findings_total": len(active), "exempted_total": len(outcome.exempted),
            "expired_exemptions": len(outcome.expired_exemptions), "severity": counts,
            "blocking": counts.get("blocker", 0) > 0,
            "rules_sha256": outcome.rules_sha256, "config_sha256": outcome.config_digest},
        "findings": [finding.to_dict() for finding in active],
        "exempted_findings": [hit.to_dict() for hit in outcome.exempted],
        "expired_exemptions": outcome.expired_exemptions,
        "parse_warnings": outcome.parse_warnings,
        "discovery_errors": outcome.discovery_errors,
        "rollback": outcome.rollback, "idempotency": outcome.idempotency,
        "diff": outcome.diff, "rule_snapshots": outcome.rule_snapshots,
        "notices": outcome.notices,
    }

def render_json(outcome: AuditOutcome) -> str:
    return json.dumps(build_report(outcome), ensure_ascii=False, indent=2) + "\n"

def write_json(outcome: AuditOutcome, output_dir: Path) -> Path:
    path = output_dir / "findings.json"
    atomic_write_text(path, render_json(outcome))
    return path
