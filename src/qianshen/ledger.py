"""SQLite 审计台账。每次运行在单个事务中写入全部记录。"""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from typing import Any
from . import __version__
from .models import AuditOutcome
from .util import canonical_json, ensure_dir
SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,
  started_at TEXT NOT NULL, ended_at TEXT NOT NULL, tool_version TEXT NOT NULL,
  project TEXT NOT NULL, dialect TEXT NOT NULL, fail_on TEXT NOT NULL,
  config_sha256 TEXT NOT NULL, rules_sha256 TEXT NOT NULL, input_sha256 TEXT NOT NULL,
  input_dir TEXT NOT NULL, conclusion TEXT NOT NULL, exit_code INTEGER NOT NULL,
  files_count INTEGER NOT NULL, findings_count INTEGER NOT NULL,
  blocking_count INTEGER NOT NULL, summary_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS files (
  run_pk INTEGER NOT NULL, rel_path TEXT NOT NULL, version INTEGER,
  direction TEXT NOT NULL, description TEXT NOT NULL, size_bytes INTEGER NOT NULL,
  line_count INTEGER NOT NULL, sha256 TEXT NOT NULL, naming_error TEXT,
  mtime_placeholder TEXT NOT NULL, PRIMARY KEY (run_pk, rel_path));
CREATE TABLE IF NOT EXISTS statements (
  run_pk INTEGER NOT NULL, file_rel TEXT NOT NULL, seq INTEGER NOT NULL,
  start_line INTEGER NOT NULL, end_line INTEGER NOT NULL, kind TEXT NOT NULL,
  ast_kind TEXT NOT NULL, is_ddl INTEGER NOT NULL, is_dml INTEGER NOT NULL,
  is_transaction INTEGER NOT NULL, objects_json TEXT NOT NULL, actions_json TEXT NOT NULL,
  summary TEXT NOT NULL, sha256 TEXT NOT NULL, parse_ok INTEGER NOT NULL,
  parse_warning TEXT, source TEXT NOT NULL, attrs_json TEXT NOT NULL,
  PRIMARY KEY (run_pk, file_rel, seq));
CREATE TABLE IF NOT EXISTS findings (
  run_pk INTEGER NOT NULL, fingerprint TEXT NOT NULL, rule_id TEXT NOT NULL,
  title TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL,
  file_rel TEXT NOT NULL, version INTEGER, direction TEXT NOT NULL,
  statement_seq INTEGER, line_start INTEGER NOT NULL, line_end INTEGER NOT NULL,
  object_name TEXT NOT NULL, evidence TEXT NOT NULL, suggestion TEXT NOT NULL,
  source TEXT NOT NULL, confidence TEXT NOT NULL, status TEXT NOT NULL,
  exemption_id TEXT, PRIMARY KEY (run_pk, fingerprint, rule_id));
CREATE TABLE IF NOT EXISTS rule_snapshots (
  run_pk INTEGER NOT NULL, rule_id TEXT NOT NULL, severity TEXT NOT NULL,
  category TEXT NOT NULL, enabled INTEGER NOT NULL, rule_json TEXT NOT NULL,
  PRIMARY KEY (run_pk, rule_id));
CREATE TABLE IF NOT EXISTS exemptions_applied (
  run_pk INTEGER NOT NULL, exemption_id TEXT NOT NULL, finding_fingerprint TEXT NOT NULL,
  rule_id TEXT NOT NULL, path_glob TEXT, version INTEGER, reason TEXT NOT NULL,
  expires_on TEXT NOT NULL, PRIMARY KEY (run_pk, exemption_id, finding_fingerprint));
CREATE TABLE IF NOT EXISTS diffs (
  run_pk INTEGER NOT NULL, category TEXT NOT NULL, fingerprint TEXT NOT NULL,
  rule_id TEXT NOT NULL, severity TEXT NOT NULL, file_rel TEXT NOT NULL,
  summary TEXT NOT NULL, PRIMARY KEY (run_pk, category, fingerprint));
CREATE TABLE IF NOT EXISTS errors (
  run_pk INTEGER NOT NULL, stage TEXT NOT NULL, file_rel TEXT, line INTEGER,
  code TEXT NOT NULL, message TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_pk);
CREATE INDEX IF NOT EXISTS idx_runs_run_id ON runs(run_id);
"""

def connect(path: Path) -> sqlite3.Connection:
    ensure_dir(path.parent)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    return connection

def previous_findings(path: Path, exclude_run_id: str | None = None) -> dict[str, Any] | None:
    connection = connect(path)
    try:
        if exclude_run_id:
            row = connection.execute(
                "SELECT * FROM runs WHERE run_id != ? ORDER BY id DESC LIMIT 1",
                (exclude_run_id,),
            ).fetchone()
        else:
            row = connection.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return None
        items = connection.execute(
            "SELECT fingerprint, rule_id, severity, file_rel, status FROM findings "
            "WHERE run_pk = ? ORDER BY fingerprint, rule_id", (row["id"],)
        ).fetchall()
        return {
            "run_pk": row["id"],
            "run_id": row["run_id"],
            "findings": [dict(item) for item in items],
        }
    finally:
        connection.close()

def _insert_findings(connection: sqlite3.Connection, run_pk: int, outcome: AuditOutcome) -> None:
    connection.executemany(
        "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            (
                run_pk, finding.fingerprint, finding.rule_id, finding.title,
                finding.severity, finding.category, finding.file, finding.version,
                finding.direction, finding.statement_seq, finding.line_start,
                finding.line_end, finding.object_name, finding.evidence,
                finding.suggestion, finding.source, finding.confidence,
                finding.status, finding.exemption_id,
            )
            for finding in outcome.findings
        ],
    )

def write_run(outcome: AuditOutcome, path: Path) -> int:
    counts = outcome.severity_counts()
    summary = {
        "severity_counts": counts,
        "findings_total": len(outcome.findings),
        "exempted": len(outcome.exempted),
        "version": outcome.version_result,
        "diff": outcome.diff.get("summary", {}),
        "idempotency_score": outcome.idempotency.get("score"),
    }
    connection = connect(path)
    try:
        with connection:
            cursor = connection.execute(
                "INSERT INTO runs (run_id, started_at, ended_at, tool_version, project, "
                "dialect, fail_on, config_sha256, rules_sha256, input_sha256, input_dir, "
                "conclusion, exit_code, files_count, findings_count, blocking_count, "
                "summary_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    outcome.run_id, outcome.started_at, outcome.ended_at, __version__,
                    "qianshen-audit", outcome.dialect, outcome.fail_on,
                    outcome.config_digest, outcome.rules_sha256,
                    outcome.input_summary.get("sha256", ""),
                    outcome.input_summary.get("root", ""), outcome.conclusion,
                    outcome.exit_code, len(outcome.files), len(outcome.findings),
                    counts.get("blocker", 0), canonical_json(summary),
                ),
            )
            run_pk = int(cursor.lastrowid)
            connection.executemany(
                "INSERT INTO files VALUES (?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        run_pk, file.rel_path, file.version, file.direction,
                        file.description, file.size_bytes, file.line_count,
                        file.sha256, file.naming_error, file.mtime_placeholder,
                    )
                    for file in outcome.files
                ],
            )
            connection.executemany(
                "INSERT INTO statements VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        run_pk, stmt.file_rel, stmt.seq, stmt.start_line, stmt.end_line,
                        stmt.kind, stmt.ast_kind, int(stmt.is_ddl), int(stmt.is_dml),
                        int(stmt.is_transaction), canonical_json(stmt.objects),
                        canonical_json(stmt.actions), stmt.summary, stmt.sha256,
                        int(stmt.parse_ok), stmt.parse_warning, stmt.source,
                        canonical_json(stmt.attrs),
                    )
                    for stmt in outcome.statements
                ],
            )
            _insert_findings(connection, run_pk, outcome)
            connection.executemany(
                "INSERT INTO rule_snapshots VALUES (?,?,?,?,?,?)",
                [(run_pk, item["id"], item["severity"], item["category"],
                  int(item["enabled"]), canonical_json(item))
                 for item in outcome.rule_snapshots])
            connection.executemany(
                "INSERT INTO exemptions_applied VALUES (?,?,?,?,?,?,?,?)",
                [(run_pk, hit.exemption.id, hit.finding.fingerprint,
                  hit.finding.rule_id, hit.exemption.path_glob,
                  hit.exemption.version, hit.exemption.reason,
                  hit.exemption.expires_on) for hit in outcome.exempted])
            connection.executemany(
                "INSERT INTO diffs VALUES (?,?,?,?,?,?,?)",
                [(run_pk, item["category"], item["fingerprint"], item["rule_id"],
                  item["severity"], item["file"], item["summary"])
                 for item in outcome.diff.get("items", [])])
            errors = list(outcome.discovery_errors) + list(outcome.parse_warnings)
            connection.executemany(
                "INSERT INTO errors (run_pk, stage, file_rel, line, code, message) "
                "VALUES (?,?,?,?,?,?)",
                [(run_pk, item.get("stage", ""), item.get("file"), item.get("line"),
                  item.get("code", ""), str(item.get("message", ""))[:300])
                 for item in errors])
        return run_pk
    except sqlite3.Error:
        connection.rollback()
        raise
    finally:
        connection.close()
