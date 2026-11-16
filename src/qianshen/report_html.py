"""自包含 HTML 报告：内联 CSS，无外部资源、无脚本。"""
from __future__ import annotations
import html
from pathlib import Path
from typing import Any
from . import TOOL_TITLE, __version__
from .models import AuditOutcome
from .report_json import sorted_active
from .util import atomic_write_text, truncate
STYLE = """
:root { --ink:#17212b; --muted:#5b6875; --line:#d8dee5; --bg:#fff; --panel:#f5f7f9; --blocker:#9f1d2c; --warning:#8a5a00; --info:#245f8f; }
* { box-sizing:border-box; }
body { margin:0 auto; max-width:1180px; padding:32px 24px 64px; background:var(--bg); color:var(--ink); font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; line-height:1.55; }
h1 { font-size:28px; margin:0 0 4px; letter-spacing:-.02em; }
h2 { font-size:20px; margin:32px 0 12px; padding-bottom:6px; border-bottom:1px solid var(--line); }
h3 { font-size:16px; margin:20px 0 8px; }
p, li { font-size:14px; }
.sub { color:var(--muted); margin:0 0 20px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px; }
.card b { display:block; font-size:22px; }
.card span { color:var(--muted); font-size:12px; }
table { width:100%; border-collapse:collapse; margin:8px 0 16px; font-size:13px; }
th, td { border:1px solid var(--line); padding:7px 8px; text-align:left; vertical-align:top; }
th { background:var(--panel); font-weight:600; }
code, pre { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:12px; }
code { background:var(--panel); padding:1px 4px; border-radius:3px; }
pre { background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:12px; overflow:auto; }
.badge { display:inline-block; border-radius:999px; padding:1px 8px; font-size:11px; font-weight:600; }
.blocker { color:var(--blocker); border:1px solid var(--blocker); }
.warning { color:var(--warning); border:1px solid var(--warning); }
.info { color:var(--info); border:1px solid var(--info); }
.note { color:var(--muted); font-size:12px; }
ul { margin:6px 0 12px; padding-left:22px; }
"""
CONCLUSIONS = {"blocked": "阻断：存在达到退出阈值的发现", "passed": "通过：没有达到退出阈值的发现"}

def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))

def _finding_rows(findings: list[Any]) -> str:
    rows = ["".join((
        "<tr>", f'<td><span class="badge {_e(f.severity)}">{_e(f.severity)}</span></td>',
        f"<td><code>{_e(f.rule_id)}</code></td>",
        f"<td><code>{_e(f.file)}:{f.line_start}</code></td>",
        f"<td>{_e(f.object_name)}</td>",
        f"<td>{_e(truncate(f.evidence, 130))}</td></tr>")) for f in findings]
    if not rows: return "<p>无活跃发现。</p>"
    return ("<table><thead><tr><th>严重级别</th><th>规则</th><th>位置</th><th>对象</th>"
            "<th>证据</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")

def render_html(outcome: AuditOutcome) -> str:
    active = sorted_active(outcome)
    counts = outcome.severity_counts()
    parts = [
        "<!doctype html>", '<html lang="zh-CN"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_e(TOOL_TITLE)}评审报告</title><style>{STYLE}</style></head><body>",
        f"<h1>{_e(TOOL_TITLE)}评审报告</h1>",
        f'<p class="sub">{_e(CONCLUSIONS.get(outcome.conclusion, outcome.conclusion))}'
        f"　运行 {_e(outcome.run_id)}　时钟 {_e(outcome.started_at)}</p>",
        '<div class="cards">',
        f'<div class="card"><b>{counts.get("blocker", 0)}</b><span>blocker</span></div>',
        f'<div class="card"><b>{counts.get("warning", 0)}</b><span>warning</span></div>',
        f'<div class="card"><b>{counts.get("info", 0)}</b><span>info</span></div>',
        f'<div class="card"><b>{len(outcome.exempted)}</b><span>已豁免</span></div>',
        f'<div class="card"><b>{len(outcome.files)}</b><span>迁移文件</span></div>',
        f'<div class="card"><b>{outcome.idempotency.get("score", 100)}</b><span>幂等性分</span></div>',
        "</div>", "<h2>运行信息</h2><ul>",
        f"<li>方言 <code>{_e(outcome.dialect)}</code>；退出阈值 <code>{_e(outcome.fail_on)}</code>；退出码 {outcome.exit_code}</li>",
        f"<li>输入 <code>{_e(outcome.input_summary.get('root', ''))}</code>；语句 {len(outcome.statements)} 条</li>",
        f"<li>规则集指纹 <code>{_e(outcome.rules_sha256[:16])}</code>；工具版本 <code>{_e(__version__)}</code></li>",
        "</ul>", "<h2>阻断项</h2>",
        _finding_rows([x for x in active if x.severity == "blocker"]),
        "<h2>重点发现</h2>", _finding_rows(active[:40]),
    ]
    if len(active) > 40: parts.append(f'<p class="note">仅展示前 40 条；完整列表见 findings.json（共 {len(active)} 条）。</p>')
    parts.append("<h2>回滚配对</h2>")
    if not outcome.rollback.get("enabled"):
        parts.append("<p>回滚配对检查未启用。</p>")
    elif outcome.rollback.get("pairs"):
        rows = "".join("".join((
            "<tr>", f"<td>{_e(p['version'])}</td><td><code>{_e(p['up'])}</code></td>",
            f"<td><code>{_e(p.get('down') or '')}</code></td><td>{_e(p['status'])}</td>",
            f"<td>{_e(p.get('evidence_source', ''))}</td>",
            f"<td>{_e(', '.join(p.get('missing_objects', [])))}</td></tr>")) for p in outcome.rollback["pairs"])
        parts.append("<table><thead><tr><th>版本</th><th>up</th><th>down</th><th>状态</th>"
                     f"<th>证据来源</th><th>缺失对象</th></tr></thead><tbody>{rows}</tbody></table>")
    else:
        parts.append("<p>没有可核验的 up/down 配对。</p>")
    for notice in outcome.rollback.get("notices", []):
        parts.append(f'<p class="note">{_e(notice)}</p>')
    idem = outcome.idempotency
    parts += ["<h2>幂等性摘要</h2>",
              f"<p>工程可解释分：<strong>{idem.get('score', 100)} / 100</strong></p>",
              f'<p class="note">{_e(idem.get("method", ""))}</p>']
    if idem.get("reason_counts"):
        parts.append("<ul>" + "".join(
            f"<li><code>{_e(c)}</code>：{n}</li>" for c, n in sorted(idem["reason_counts"].items())) + "</ul>")
    parts.append("<h2>豁免说明</h2>")
    if outcome.exempted:
        rows = "".join("".join((
            "<tr>", f"<td><code>{_e(h.exemption.id)}</code></td>",
            f"<td><code>{_e(h.finding.rule_id)}</code></td>",
            f"<td><code>{_e(h.finding.file)}</code></td>",
            f"<td>{_e(h.exemption.reason)}</td><td>{_e(h.exemption.expires_on)}</td></tr>"))
            for h in outcome.exempted)
        parts += ["<table><thead><tr><th>豁免 ID</th><th>规则</th><th>文件</th><th>原因</th>"
                  f"<th>到期日</th></tr></thead><tbody>{rows}</tbody></table>",
                  '<p class="note">豁免项在 findings.json 中单独列出，未被静默丢弃。</p>']
    else:
        parts.append("<p>本次没有豁免命中。</p>")
    if outcome.expired_exemptions:
        parts.append("<ul>" + "".join(
            f"<li>已过期 <code>{_e(i['id'])}</code>，到期日 {_e(i['expires_on'])}</li>"
            for i in outcome.expired_exemptions) + "</ul>")
    diff = outcome.diff
    parts += ["<h2>运行间差异</h2>", "<p>"
              + (f"对比运行 <code>{_e(diff.get('previous_run_id'))}</code>。"
                 if diff.get("baseline_available") else "没有可用的上一次运行。")
              + "</p><ul>" + "".join(
                  f"<li>{c}：{diff.get('counts', {}).get(c, 0)}</li>"
                  for c in ("new", "fixed", "persistent", "exempted")) + "</ul>",
              "<h2>解析警告与输入错误</h2>"]
    if outcome.parse_warnings or outcome.discovery_errors:
        parts.append("<ul>")
        for item in outcome.parse_warnings:
            parts.append(f"<li><code>{_e(item['file'])}:{item['line']}</code> {_e(item['code'])}："
                         f"{_e(truncate(item['message'], 140))}</li>")
        for item in outcome.discovery_errors:
            parts.append(f"<li><code>{_e(item.get('file', ''))}</code> {_e(item['code'])}：{_e(item['message'])}</li>")
        parts.append("</ul>")
    else:
        parts.append("<p>无。</p>")
    if outcome.notices:
        parts.append("<h2>提示</h2><ul>" + "".join(f"<li>{_e(x)}</li>" for x in outcome.notices) + "</ul>")
    parts += ["<h2>复现命令</h2>", f"<pre>{_e(outcome.reproduce_command)}</pre>",
              '<p class="note">报告仅包含截断证据与定位信息，不复制完整 SQL 原文。</p>',
              "</body></html>"]
    return "\n".join(parts) + "\n"

def write_html(outcome: AuditOutcome, output_dir: Path) -> Path:
    path = output_dir / "report.html"
    atomic_write_text(path, render_html(outcome))
    return path
