"""审计流水线：发现、解析、规则、回滚、幂等、豁免、差异、台账与报告。"""
from __future__ import annotations
import shlex
import sqlite3
from pathlib import Path
from . import __version__
from .cache import AuditCache
from .config import Config
from .diffing import compute_diff
from .discovery import discover
from .exemptions import apply_exemptions, load_exemptions
from .idempotency import calculate_idempotency
from .ledger import previous_findings, write_run
from .models import AuditOutcome
from .report_html import write_html
from .report_json import write_json
from .report_markdown import write_markdown
from .rollback_pair import check_rollback_pairs
from .rules_engine import evaluate_rules, load_rules
from .sql_parse import parse_all
from .util import (
    QianshenError, canonical_json, ensure_dir, finding_sort_key, parse_iso_datetime,
    relative_display, severity_rank, sha256_text,
)
from .version_chain import build_input_summary, check_version_chain

def _reproduce(config: Config) -> str:
    parts = [
        "python", "-m", "qianshen", "audit",
        "--config", relative_display(config.path),
        "--migrations", relative_display(config.migrations_dir),
        "--out", relative_display(config.output_dir),
        "--ledger", relative_display(config.ledger_path),
        "--now", config.clock,
    ]
    return " ".join(shlex.quote(part) for part in parts)

def _exit_code(findings: list, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = severity_rank(fail_on)
    return 1 if any(severity_rank(item.severity) >= threshold for item in findings) else 0

def run_audit(config: Config) -> AuditOutcome:
    files, discovery_errors = discover(config)
    cache = AuditCache.open(config)
    statements, parse_warnings = parse_all(files, config.dialect, cache=cache)
    version_findings, version_result = check_version_chain(files, config)
    rules_bundle = load_rules(config)
    rule_findings = evaluate_rules(rules_bundle, files, statements, config)
    rollback_findings, rollback_result = check_rollback_pairs(files, statements, config)
    idempotency = calculate_idempotency(files, statements)
    exemptions = load_exemptions(config)
    clock = parse_iso_datetime(config.clock)
    pre_exemption = version_findings + rule_findings + rollback_findings
    active, hits, expired, expired_findings = apply_exemptions(
        pre_exemption, exemptions, clock.date()
    )
    findings = active + expired_findings + [hit.finding for hit in hits]
    findings.sort(key=finding_sort_key)
    input_summary = build_input_summary(files, config)
    finding_state = canonical_json([
        [item.fingerprint, item.status] for item in findings
    ])
    run_id = "qn-" + sha256_text("|".join([
        __version__, config.clock, config.config_digest, rules_bundle.sha256,
        str(input_summary["sha256"]), finding_state,
    ]))[:20]
    try:
        previous = previous_findings(config.ledger_path, exclude_run_id=run_id)
    except sqlite3.Error as exc:
        raise QianshenError(f"读取台账失败: {exc}", exit_code=3) from exc
    diff = compute_diff(findings, previous)
    exit_code = _exit_code(active, config.fail_on)
    conclusion = "blocked" if exit_code == 1 else "passed"
    notices: list[str] = list(rollback_result.get("notices", []))
    if len(files) and not statements:
        notices.append("未从输入文件中解析出语句，请检查文件内容。")
    outcome = AuditOutcome(
        run_id=run_id, started_at=config.clock, ended_at=config.clock,
        config_digest=config.config_digest, rules_sha256=rules_bundle.sha256,
        input_summary=input_summary, files=files, statements=statements,
        findings=findings, exempted=hits, expired_exemptions=expired,
        parse_warnings=parse_warnings, discovery_errors=discovery_errors,
        version_result=version_result, rollback=rollback_result,
        idempotency=idempotency, diff=diff,
        rule_snapshots=rules_bundle.snapshots, exit_code=exit_code,
        conclusion=conclusion, fail_on=config.fail_on, dialect=config.dialect,
        config_summary=config.summary(), reproduce_command=_reproduce(config),
        notices=notices,
    )
    try:
        ensure_dir(config.output_dir)
        write_json(outcome, config.output_dir)
        write_markdown(outcome, config.output_dir)
        write_html(outcome, config.output_dir)
        write_run(outcome, config.ledger_path)
    except (OSError, sqlite3.Error) as exc:
        raise QianshenError(f"报告或台账写入失败: {exc}", exit_code=3) from exc
    return outcome

def outcome_json(outcome: AuditOutcome) -> str:
    """CLI 摘要用的紧凑 JSON。"""
    return canonical_json({
        "run_id": outcome.run_id,
        "conclusion": outcome.conclusion,
        "exit_code": outcome.exit_code,
        "severity": outcome.severity_counts(),
        "findings": len(outcome.active_findings),
        "exempted": len(outcome.exempted),
        "idempotency_score": outcome.idempotency.get("score"),
        "outputs": ["findings.json", "report.md", "report.html"],
    })
