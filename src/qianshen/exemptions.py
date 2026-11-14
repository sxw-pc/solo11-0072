"""豁免文件加载、过期处理与命中记录。"""
from __future__ import annotations
from datetime import date
from pathlib import Path
from typing import Any
import yaml
from .config import Config
from .models import Exemption, ExemptionHit, Finding, make_finding
from .util import QianshenError, parse_iso_date, path_matches

def load_exemptions(config: Config) -> list[Exemption]:
    if config.exemptions_file is None:
        return []
    try:
        raw = yaml.safe_load(config.exemptions_file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise QianshenError(f"豁免文件读取失败: {exc}") from exc
    items = raw.get("exemptions") if isinstance(raw, dict) else raw
    if items is None:
        return []
    if not isinstance(items, list):
        raise QianshenError("豁免文件必须包含 exemptions 列表")
    exemptions: list[Exemption] = []
    seen: set[str] = set()
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            raise QianshenError("豁免条目必须是映射")
        exemption_id = str(item.get("id") or f"ex-{index:03d}")
        if exemption_id in seen:
            raise QianshenError(f"豁免 ID 重复: {exemption_id}")
        seen.add(exemption_id)
        reason = str(item.get("reason") or "").strip()
        expires_on = str(item.get("expires_on") or "").strip()
        if not reason:
            raise QianshenError(f"豁免 {exemption_id} 必须包含 reason")
        if not expires_on:
            raise QianshenError(f"豁免 {exemption_id} 必须包含 expires_on")
        try:
            expires_date = parse_iso_date(expires_on)
        except ValueError as exc:
            raise QianshenError(f"豁免 {exemption_id} 的 expires_on 无效: {exc}") from exc
        version = item.get("version")
        if version is not None:
            if not isinstance(version, int):
                raise QianshenError(f"豁免 {exemption_id} 的 version 必须是整数")
        rule_id = item.get("rule_id")
        path_glob = item.get("path_glob")
        fingerprint = item.get("fingerprint")
        if not any(isinstance(value, str) and value for value in (rule_id, path_glob, fingerprint)):
            raise QianshenError(f"豁免 {exemption_id} 至少需要 rule_id、path_glob 或 fingerprint")
        exemptions.append(Exemption(
            id=exemption_id,
            rule_id=str(rule_id) if rule_id else None,
            path_glob=str(path_glob) if path_glob else None,
            version=version,
            fingerprint=str(fingerprint) if fingerprint else None,
            reason=reason,
            expires_on=expires_on,
            expires_date=expires_date,
        ))
    return exemptions

def _matches(exemption: Exemption, finding: Finding) -> bool:
    if exemption.rule_id and exemption.rule_id != finding.rule_id:
        return False
    if exemption.path_glob and not path_matches(finding.file, exemption.path_glob):
        return False
    if exemption.version is not None and exemption.version != finding.version:
        return False
    if exemption.fingerprint and exemption.fingerprint != finding.fingerprint:
        return False
    return True

def apply_exemptions(
    findings: list[Finding], exemptions: list[Exemption], clock: date
) -> tuple[list[Finding], list[ExemptionHit], list[dict[str, Any]], list[Finding]]:
    active: list[Finding] = []
    hits: list[ExemptionHit] = []
    expired: list[dict[str, Any]] = []
    expired_findings: list[Finding] = []
    valid: list[Exemption] = []
    for exemption in exemptions:
        if exemption.expires_date < clock:
            expired.append({
                "id": exemption.id,
                "rule_id": exemption.rule_id,
                "path_glob": exemption.path_glob,
                "version": exemption.version,
                "reason": exemption.reason,
                "expires_on": exemption.expires_on,
            })
            expired_findings.append(make_finding(
                rule_id="config.exemption_expired",
                title="豁免已过期",
                severity="warning",
                category="configuration",
                file=exemption.path_glob or ".",
                version=exemption.version,
                direction="mixed",
                object_name=exemption.id,
                evidence=f"豁免 {exemption.id} 已于 {exemption.expires_on} 过期",
                suggestion="更新豁免依据与有效期，或移除豁免并处理对应发现。",
                source="config",
                detail=f"expired-exemption:{exemption.id}:{exemption.expires_on}",
            ))
        else:
            valid.append(exemption)
    valid.sort(key=lambda item: item.id)
    for finding in findings:
        matched = next((item for item in valid if _matches(item, finding)), None)
        if matched is None:
            active.append(finding)
        else:
            finding.exempt(matched.id)
            hits.append(ExemptionHit(matched, finding))
    hits.sort(key=lambda hit: (hit.exemption.id, hit.finding.fingerprint))
    return active, hits, expired, expired_findings
