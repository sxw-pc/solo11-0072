"""离线演示：对六类 fixture 逐一评审，生成报告、台账与索引页。"""
from __future__ import annotations
import html
import json
import os
from pathlib import Path
from typing import Any
import yaml
from . import TOOL_TITLE, __version__
from .audit import run_audit
from .config import load_config
from .util import QianshenError, atomic_write_text, ensure_dir
FIXTURES = (
    ("good", "migrations_good", "正常迁移，含安全变更与回滚配对"),
    ("risky", "migrations_risky", "危险 DDL/DML、不可逆操作与低幂等性"),
    ("conflict", "migrations_conflict", "版本重复、缺口、命名异常与混合布局"),
    ("missing_down", "migrations_missing_down", "回滚缺失、空回滚与对象不匹配"),
    ("dialects", "migrations_dialects", "三种方言声明与解析降级展示"),
    ("exempted", "migrations_exempted", "有效豁免、过期豁免与未豁免发现"),
)

def _project_root() -> Path:
    for candidate in (Path.cwd(), Path(__file__).resolve().parents[2]):
        if (candidate / "fixtures").is_dir() and (candidate / "rules" / "default.yml").is_file():
            return candidate
    raise QianshenError("无法定位 fixtures/ 与 rules/；请在项目根目录运行 demo", exit_code=2)

def _relative(target: Path, base: Path) -> str:
    try:
        return Path(os.path.relpath(target, base)).as_posix()
    except ValueError:  # Windows 跨盘符：改用绝对 POSIX 路径
        return target.resolve().as_posix()

def _write_config(
    output_root: Path, name: str, fixture: str, source: Any, now: str
) -> Path:
    directory = output_root / name
    ensure_dir(directory)
    root = _project_root()
    exemptions = (root / "fixtures" / "exemptions.yml"
                  if fixture == "migrations_exempted" else None)
    config_data = {
        "project": "qianshen-audit", "version": 1,
        "migrations_dir": _relative(root / "fixtures" / fixture, directory),
        "dialect": "postgres", "naming": {"mode": "auto", "version_width": 4},
        "ignore": {"dirs": source.ignore.dirs, "globs": source.ignore.globs,
                   "paths": source.ignore.paths},
        "rules_file": _relative(root / "rules" / "default.yml", directory),
        "exemptions_file": _relative(exemptions, directory) if exemptions else None,
        "baseline_file": None, "output_dir": ".", "ledger_path": "ledger.sqlite3",
        "fail_on": "blocker", "clock": now, "large_tables": list(source.large_tables),
        "permissions": {"allow_grants": source.allow_grants},
        "pairing": {"check_rollback": True},
        "irreversible_approvals": list(source.irreversible_approvals),
        "rule_overrides": {},
    }
    path = directory / "audit-config.yml"
    atomic_write_text(path, yaml.safe_dump(config_data, allow_unicode=True, sort_keys=False))
    return path

def _index_html(entries: list[dict[str, Any]], now: str) -> str:
    rows = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(item[k]))}</td>" for k in
        ("fixture", "description", "exit_code", "findings", "exempted", "idempotency_score"))
        + f'<td><a href="{item["name"]}/report.html">HTML</a> · '
        f'<a href="{item["name"]}/report.md">Markdown</a> · '
        f'<a href="{item["name"]}/findings.json">JSON</a></td></tr>'
        for item in entries)
    style = (
        "body{max-width:1100px;margin:36px auto;padding:0 24px;color:#17212b;"
        "font-family:ui-sans-serif,system-ui,sans-serif;line-height:1.55}"
        "table{width:100%;border-collapse:collapse;font-size:14px}"
        "th,td{border:1px solid #d8dee5;padding:9px;text-align:left}"
        "th{background:#f5f7f9}code{background:#f5f7f9;padding:1px 4px}"
        ".note{color:#5b6875;font-size:13px}"
    )
    return (
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        f"<title>{html.escape(TOOL_TITLE)}演示</title><style>{style}</style></head><body>"
        f"<h1>{html.escape(TOOL_TITLE)}离线演示</h1>"
        f"<p class=\"note\">工具版本 {__version__} · 固定时钟 {html.escape(now)} · "
        "每个目录独立 SQLite 台账，运行期无网络访问。</p>"
        "<table><thead><tr><th>Fixture</th><th>场景</th><th>退出码</th><th>活跃发现</th>"
        f"<th>已豁免</th><th>幂等分</th><th>报告</th></tr></thead><tbody>{rows}</tbody></table>"
        "<p class=\"note\">退出码 0 表示无阻断，1 表示存在阻断，2 表示配置/输入错误，"
        "3 表示内部错误。演示命令本身在全部场景完成后返回 0。</p>"
        "</body></html>\n"
    )

def run_demo(output: str | Path, *, now: str = "2026-01-01T00:00:00Z") -> dict[str, Any]:
    output_root = Path(output).expanduser()
    ensure_dir(output_root)
    root = _project_root()
    source = load_config(root / "qianshen.yml", now_override=now)
    entries: list[dict[str, Any]] = []
    for name, fixture, description in FIXTURES:
        fixture_dir = root / "fixtures" / fixture
        if not fixture_dir.is_dir():
            raise QianshenError(f"缺少演示 fixture: {fixture}")
        config_path = _write_config(output_root, name, fixture, source, now)
        config = load_config(config_path)
        outcome = run_audit(config)
        entries.append({
            "name": name, "fixture": fixture, "description": description,
            "run_id": outcome.run_id, "conclusion": outcome.conclusion,
            "exit_code": outcome.exit_code, "findings": len(outcome.active_findings),
            "exempted": len(outcome.exempted),
            "expired_exemptions": len(outcome.expired_exemptions),
            "idempotency_score": outcome.idempotency.get("score"),
            "outputs": [f"{name}/{n}" for n in
                        ("findings.json", "report.md", "report.html", "ledger.sqlite3")],
        })
    summary = {
        "schema_version": "1.0",
        "tool": {"name": "qianshen-audit", "version": __version__},
        "generated_at": now,
        "fixtures": entries,
    }
    atomic_write_text(
        output_root / "demo_summary.json",
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
    )
    atomic_write_text(output_root / "index.html", _index_html(entries, now))
    text = "\n".join([
        f"{TOOL_TITLE} demo 完成：{len(entries)} 个 fixture",
        *[
            f"  {item['name']:<12} exit={item['exit_code']} findings={item['findings']} "
            f"exempted={item['exempted']} score={item['idempotency_score']}"
            for item in entries
        ],
    ])
    return {"output_dir": output_root, "entries": entries, "summary_text": text}
