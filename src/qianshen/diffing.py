"""基于稳定发现指纹的运行间差异。行号与文本位置不参与比较。"""
from __future__ import annotations
from typing import Any
from .models import Finding
from .util import severity_rank
CATEGORY_ORDER = ("new", "fixed", "persistent", "exempted")

def compute_diff(findings: list[Finding], previous: dict[str, Any] | None) -> dict[str, Any]:
    previous_rows = previous.get("findings", []) if previous else []
    previous_active = {
        row["fingerprint"] for row in previous_rows if row.get("status") == "active"
    }
    previous_all = {row["fingerprint"]: row for row in previous_rows}
    current_active = [finding for finding in findings if finding.status == "active"]
    current_exempted = [finding for finding in findings if finding.status == "exempted"]
    active_map = {finding.fingerprint: finding for finding in current_active}
    exempted_map = {finding.fingerprint: finding for finding in current_exempted}
    items: list[dict[str, Any]] = []
    for finding in current_active:
        category = "persistent" if finding.fingerprint in previous_active else "new"
        items.append(_item(category, finding))
    for finding in current_exempted:
        if finding.fingerprint in previous_all and finding.fingerprint not in previous_active:
            continue
        items.append(_item("exempted", finding))
    for row in previous_rows:
        if row.get("status") != "active":
            continue
        fingerprint = row["fingerprint"]
        if fingerprint in active_map or fingerprint in exempted_map:
            continue
        items.append({"category": "fixed", "fingerprint": fingerprint,
            "rule_id": row.get("rule_id", ""), "severity": row.get("severity", "info"),
            "file": row.get("file_rel", ""), "summary": "上次运行存在，本次未复现"})
    items.sort(key=lambda item: (
        CATEGORY_ORDER.index(item["category"]), -severity_rank(item["severity"]),
        item["file"], item["fingerprint"]))
    counts = {category: 0 for category in CATEGORY_ORDER}
    for item in items:
        counts[item["category"]] += 1
    return {
        "baseline_available": previous is not None,
        "previous_run_id": previous.get("run_id") if previous else None,
        "basis": "fingerprint", "category_order": list(CATEGORY_ORDER),
        "counts": counts, "items": items,
        "summary": {"counts": counts,
                    "previous_run_id": previous.get("run_id") if previous else None},
    }

def _item(category: str, finding: Finding) -> dict[str, Any]:
    return {"category": category, "fingerprint": finding.fingerprint,
            "rule_id": finding.rule_id, "severity": finding.severity,
            "file": finding.file, "summary": finding.evidence}
