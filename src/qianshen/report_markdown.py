"""人类可复核的 Markdown 报告。"""
from __future__ import annotations
from pathlib import Path
from typing import Any
from . import TOOL_TITLE, __version__
from .models import AuditOutcome
from .report_json import sorted_active
from .util import atomic_write_text, finding_sort_key, truncate
CONCLUSIONS = {"blocked": "阻断：存在达到退出阈值的发现", "passed": "通过：没有达到退出阈值的发现"}

def _cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")

def _finding_table(findings: list[Any]) -> list[str]:
    lines = ["| 严重级别 | 规则 | 位置 | 对象 | 证据 |", "|---|---|---|---|---|"]
    for finding in findings:
        location = f"{finding.file}:{finding.line_start}"
        lines.append(
            f"| {_cell(finding.severity)} | `{_cell(finding.rule_id)}` | "
            f"`{_cell(location)}` | {_cell(finding.object_name)} | {_cell(truncate(finding.evidence, 110))} |"
        )
    return lines

def render_markdown(outcome: AuditOutcome) -> str:
    active = sorted_active(outcome)
    counts = outcome.severity_counts()
    lines: list[str] = [
        f"# {TOOL_TITLE}评审报告",
        "",
        f"- 结论：**{CONCLUSIONS.get(outcome.conclusion, outcome.conclusion)}**",
        f"- 运行 ID：`{outcome.run_id}`",
        f"- 时钟：`{outcome.started_at}`",
        f"- 方言：`{outcome.dialect}`；退出阈值：`{outcome.fail_on}`；退出码：`{outcome.exit_code}`",
        f"- 输入：`{outcome.input_summary.get('root', '')}`；文件 {len(outcome.files)} 个；语句 {len(outcome.statements)} 条",
        f"- 工具版本：`{__version__}`；规则集指纹：`{outcome.rules_sha256[:16]}`",
        "",
        "## 阻断项",
        "",
    ]
    blockers = [item for item in active if item.severity == "blocker"]
    if blockers:
        lines.extend(_finding_table(blockers))
    else:
        lines.append("无阻断级发现。")
    lines.extend([
        "",
        "## 统计汇总",
        "",
        f"- blocker：{counts.get('blocker', 0)}",
        f"- warning：{counts.get('warning', 0)}",
        f"- info：{counts.get('info', 0)}",
        f"- 已豁免：{len(outcome.exempted)}",
        f"- 过期豁免：{len(outcome.expired_exemptions)}",
        f"- 解析降级警告：{len(outcome.parse_warnings)}",
        "",
        "### 按类别",
        "",
    ])
    categories: dict[str, int] = {}
    for finding in active:
        categories[finding.category] = categories.get(finding.category, 0) + 1
    if categories:
        for category, count in sorted(categories.items()):
            lines.append(f"- `{category}`：{count}")
    else:
        lines.append("无活跃发现。")
    lines.extend(["", "## 重点发现", ""])
    if active:
        lines.extend(_finding_table(active[:40]))
        if len(active) > 40: lines.append(f"\n仅展示前 40 条；完整列表见 `findings.json`（共 {len(active)} 条）。")
    else:
        lines.append("无活跃发现。")
    lines.extend(["", "## 回滚配对", ""])
    if not outcome.rollback.get("enabled"):
        lines.append("回滚配对检查未启用。")
    else:
        pairs = outcome.rollback.get("pairs", [])
        if pairs:
            lines.extend(["| 版本 | up | down | 状态 | 证据来源 | 缺失对象 |", "|---|---|---|---|---|---|"])
            for pair in pairs:
                lines.append(
                    f"| {pair['version']} | `{_cell(pair['up'])}` | `{_cell(pair.get('down') or '')}` | "
                    f"{_cell(pair['status'])} | {_cell(pair.get('evidence_source', ''))} | "
                    f"{_cell(', '.join(pair.get('missing_objects', [])))} |")
        else:
            lines.append("没有可核验的 up/down 配对。")
    for notice in outcome.rollback.get("notices", []):
        lines.append(f"\n> {notice}")
    lines.extend(["", "## 幂等性摘要", ""])
    idem = outcome.idempotency
    lines += [f"- 工程可解释分：**{idem.get('score', 100)} / 100**", f"- 口径：{idem.get('method', '')}"]
    for code, count in sorted(idem.get("reason_counts", {}).items()):
        lines.append(f"- `{code}`：{count}")
    if not idem.get("reason_counts"): lines.append("- 未记录扣分项。")
    low = idem.get("low_score_files", [])
    if low: lines.append("- 低分文件：" + ", ".join(f"`{i['file']}`({i['score']})" for i in low))
    lines.extend(["", "## 豁免说明", ""])
    if outcome.exempted:
        lines += ["| 豁免 ID | 规则 | 文件 | 原因 | 到期日 |", "|---|---|---|---|---|"]
        for hit in outcome.exempted:
            item = hit.finding
            lines.append(
                f"| `{_cell(hit.exemption.id)}` | `{_cell(item.rule_id)}` | `{_cell(item.file)}` | "
                f"{_cell(hit.exemption.reason)} | {_cell(hit.exemption.expires_on)} |")
        lines.append("\n被豁免发现仍在 `findings.json` 的 `exempted_findings` 中单独列出。")
    else:
        lines.append("本次没有豁免命中。")
    if outcome.expired_exemptions:
        lines.append("")
        for item in outcome.expired_exemptions:
            lines.append(f"- 已过期：`{item['id']}`，到期日 {item['expires_on']}，原因：{item['reason']}")
    lines.extend(["", "## 运行间差异", ""])
    diff = outcome.diff
    if diff.get("baseline_available"):
        lines.append(f"- 对比运行：`{diff.get('previous_run_id')}`")
    else:
        lines.append("- 没有可用的上一次运行，当前结果作为新基线。")
    for category in ("new", "fixed", "persistent", "exempted"):
        lines.append(f"- {category}：{diff.get('counts', {}).get(category, 0)}")
    lines.extend(["", "## 解析警告与输入错误", ""])
    if outcome.parse_warnings:
        for warning in outcome.parse_warnings:
            lines.append(
                f"- `{_cell(warning['file'])}:{warning['line']}` "
                f"{_cell(warning['code'])}：{_cell(truncate(warning['message'], 140))}"
            )
    if outcome.discovery_errors:
        for error in outcome.discovery_errors:
            lines.append(f"- `{_cell(error.get('file', ''))}` {_cell(error['code'])}：{_cell(error['message'])}")
    if not outcome.parse_warnings and not outcome.discovery_errors: lines.append("无。")
    if outcome.notices:
        lines.extend(["", "## 提示", ""])
        for notice in outcome.notices:
            lines.append(f"- {notice}")
    lines.extend([
        "",
        "## 复现命令",
        "",
        "```bash",
        outcome.reproduce_command,
        "```",
        "",
        "> 报告仅包含截断证据与定位信息，不复制完整 SQL 原文。",
        "",
    ])
    return "\n".join(lines)

def write_markdown(outcome: AuditOutcome, output_dir: Path) -> Path:
    path = output_dir / "report.md"
    atomic_write_text(path, render_markdown(outcome))
    return path
