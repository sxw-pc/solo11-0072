"""跨模块数据模型。所有路径对外统一使用 POSIX 相对路径。"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from .util import stable_fingerprint, truncate
@dataclass
class FileInfo:
    path: Path
    rel_path: str
    version: int | None
    version_raw: str | None
    description: str
    direction: str
    size_bytes: int
    line_count: int
    sha256: str
    mtime_placeholder: str
    naming_error: str | None = None
    text: str = field(default="", repr=False)
    read_error: str | None = None
    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.rel_path,
            "version": self.version,
            "direction": self.direction,
            "description": self.description,
            "size_bytes": self.size_bytes,
            "line_count": self.line_count,
            "sha256": self.sha256,
            "mtime_placeholder": self.mtime_placeholder,
            "naming_error": self.naming_error,
        }
@dataclass
class StatementInfo:
    file_rel: str
    file_sha256: str
    version: int | None
    direction: str
    seq: int
    start_line: int
    end_line: int
    kind: str
    ast_kind: str
    objects: list[str]
    actions: list[str]
    is_ddl: bool
    is_dml: bool
    is_transaction: bool
    summary: str
    sha256: str
    parse_ok: bool
    parse_warning: str | None
    attrs: dict[str, Any] = field(default_factory=dict)
    raw: str = field(default="", repr=False)
    @property
    def source(self) -> str:
        return "ast" if self.parse_ok else "token"
    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file_rel,
            "seq": self.seq,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "kind": self.kind,
            "ast_kind": self.ast_kind,
            "objects": list(self.objects),
            "actions": list(self.actions),
            "is_ddl": self.is_ddl,
            "is_dml": self.is_dml,
            "is_transaction": self.is_transaction,
            "summary": self.summary,
            "sha256": self.sha256,
            "parse_ok": self.parse_ok,
            "parse_warning": self.parse_warning,
            "source": self.source,
            "attrs": dict(self.attrs),
        }
@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    file: str
    version: int | None
    direction: str
    statement_seq: int | None
    line_start: int
    line_end: int
    object_name: str
    evidence: str
    suggestion: str
    source: str
    confidence: str = "high"
    detail: str = ""
    status: str = "active"
    exemption_id: str | None = None
    @property
    def fingerprint(self) -> str:
        return stable_fingerprint(
            [
                self.rule_id,
                self.file,
                str(self.version or ""),
                self.direction,
                self.object_name,
                self.evidence,
                self.detail,
            ]
        )
    def exempt(self, exemption_id: str) -> None:
        self.status = "exempted"
        self.exemption_id = exemption_id
    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "file": self.file,
            "version": self.version,
            "direction": self.direction,
            "statement_seq": self.statement_seq,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "object_name": self.object_name,
            "evidence": truncate(self.evidence, 180),
            "suggestion": truncate(self.suggestion, 240),
            "source": self.source,
            "confidence": self.confidence,
            "status": self.status,
            "exemption_id": self.exemption_id,
        }

def make_finding(
    *,
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    file: str,
    version: int | None,
    direction: str,
    object_name: str,
    evidence: str,
    suggestion: str,
    source: str = "file",
    line_start: int = 1,
    line_end: int | None = None,
    statement_seq: int | None = None,
    confidence: str = "high",
    detail: str = "",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        file=file,
        version=version,
        direction=direction,
        statement_seq=statement_seq,
        line_start=max(1, int(line_start or 1)),
        line_end=max(line_start, int(line_end or line_start)),
        object_name=object_name,
        evidence=truncate(evidence, 180),
        suggestion=suggestion,
        source=source,
        confidence=confidence,
        detail=detail,
    )
@dataclass
class Rule:
    id: str
    title: str
    severity: str
    category: str
    applies_to: list[str]
    match: dict[str, Any]
    message: str
    suggestion: str
    enabled: bool = True
    dialects: list[str] = field(default_factory=list)
    directions: list[str] = field(default_factory=list)
    path_globs: list[str] = field(default_factory=list)
    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "applies_to": list(self.applies_to),
            "match": dict(self.match),
            "message": self.message,
            "suggestion": self.suggestion,
            "enabled": self.enabled,
            "dialects": list(self.dialects),
            "directions": list(self.directions),
            "path_globs": list(self.path_globs),
        }
@dataclass
class Exemption:
    id: str
    rule_id: str | None
    path_glob: str | None
    version: int | None
    fingerprint: str | None
    reason: str
    expires_on: str
    expires_date: Any = field(default=None, repr=False)
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "path_glob": self.path_glob,
            "version": self.version,
            "fingerprint": self.fingerprint,
            "reason": self.reason,
            "expires_on": self.expires_on,
        }
@dataclass
class ExemptionHit:
    exemption: Exemption
    finding: Finding
    def to_dict(self) -> dict[str, Any]:
        return {
            "exemption_id": self.exemption.id,
            "reason": self.exemption.reason,
            "expires_on": self.exemption.expires_on,
            "finding": self.finding.to_dict(),
        }
@dataclass
class AuditOutcome:
    run_id: str
    started_at: str
    ended_at: str
    config_digest: str
    rules_sha256: str
    input_summary: dict[str, Any]
    files: list[FileInfo]
    statements: list[StatementInfo]
    findings: list[Finding]
    exempted: list[ExemptionHit]
    expired_exemptions: list[dict[str, Any]]
    parse_warnings: list[dict[str, Any]]
    discovery_errors: list[dict[str, Any]]
    version_result: dict[str, Any]
    rollback: dict[str, Any]
    idempotency: dict[str, Any]
    diff: dict[str, Any]
    rule_snapshots: list[dict[str, Any]]
    exit_code: int
    conclusion: str
    fail_on: str
    dialect: str
    config_summary: dict[str, Any]
    reproduce_command: str
    notices: list[str] = field(default_factory=list)
    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.status == "active"]
    def severity_counts(self) -> dict[str, int]:
        counts = {"blocker": 0, "warning": 0, "info": 0}
        for finding in self.active_findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts
