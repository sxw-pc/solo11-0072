import json
from pathlib import Path
from qianshen.util import severity_rank
from conftest import read_json, run_case
RISKY_PAIR = {
    "0001_change.up.sql": (
        "-- SECRET_MARKER this comment must not be copied verbatim\n"
        "DROP TABLE IF EXISTS demo_old;"
    ),
    "0001_change.down.sql": "CREATE TABLE demo_old (id INT);",
}
SECTIONS = ("## 阻断项", "## 统计汇总", "## 回滚配对", "## 幂等性摘要", "## 豁免说明",
            "## 运行间差异", "## 解析警告与输入错误", "## 复现命令")

def test_json_report_is_structured_sorted_and_truncated(tmp_path: Path):
    outcome, out, _ = run_case(tmp_path, RISKY_PAIR, tag="json")
    data = read_json(out / "findings.json")
    assert data["schema_version"] == "1.0"
    assert data["run"]["conclusion"] == "blocked"
    assert data["summary"]["findings_total"] == len(outcome.active_findings)
    sort_key = lambda item: (
        -severity_rank(item["severity"]), item["version"] or 0, item["file"],
        item["line_start"], item["rule_id"], item["fingerprint"],
    )
    assert data["findings"] == sorted(data["findings"], key=sort_key)
    assert all(len(item["evidence"]) <= 180 for item in data["findings"])
    assert all(item["file"] and not Path(item["file"]).is_absolute() for item in data["findings"])
    assert "SECRET_MARKER" not in json.dumps(data, ensure_ascii=False)
    assert str(tmp_path) not in json.dumps(data, ensure_ascii=False)

def test_markdown_report_has_review_sections(tmp_path: Path):
    _, out, _ = run_case(tmp_path, RISKY_PAIR, tag="md")
    text = (out / "report.md").read_text(encoding="utf-8")
    assert all(section in text for section in SECTIONS)
    assert "阻断" in text and "```bash" in text
    assert str(tmp_path) not in text

def test_html_report_is_self_contained(tmp_path: Path):
    _, out, _ = run_case(tmp_path, RISKY_PAIR, tag="html")
    text = (out / "report.html").read_text(encoding="utf-8")
    lowered = text.lower()
    assert text.startswith("<!doctype html>") and "<style>" in text
    for token in ("<script", "<link", "<img", " src=", "http://", "https://", "@import", "url("):
        assert token not in lowered
    assert "迁签审台" in text and "SECRET_MARKER" not in text
