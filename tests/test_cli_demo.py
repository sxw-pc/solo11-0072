import json
from pathlib import Path
from qianshen.cli import main
from conftest import ROOT, make_config
RISKY_PAIR = {
    "0001_change.up.sql": "DROP TABLE IF EXISTS demo_x;",
    "0001_change.down.sql": "CREATE TABLE demo_x (id INT);",
}
SAFE_PAIR = {
    "0001_change.up.sql": "CREATE TABLE IF NOT EXISTS demo_x (id INT);",
    "0001_change.down.sql": "DROP TABLE IF EXISTS demo_x;",
}

def test_cli_returns_1_for_blockers_and_0_for_safe_input(tmp_path: Path):
    risky = make_config(tmp_path, RISKY_PAIR, tag="risky-cli", migrations_name="risky")
    assert main(["audit", "--config", str(risky), "--quiet"]) == 1
    safe = make_config(tmp_path, SAFE_PAIR, tag="safe-cli", migrations_name="safe")
    assert main(["audit", "--config", str(safe), "--quiet"]) == 0

def test_fail_on_none_suppresses_blocking_exit_code(tmp_path: Path):
    config = make_config(tmp_path, RISKY_PAIR, tag="none")
    assert main(["audit", "--config", str(config), "--fail-on", "none", "--quiet"]) == 0

def test_cli_returns_2_for_bad_config_or_missing_input(tmp_path: Path):
    assert main(["audit", "--config", str(tmp_path / "missing.yml"), "--quiet"]) == 2
    config = make_config(tmp_path, SAFE_PAIR, tag="bad-input")
    missing = tmp_path / "does-not-exist"
    assert main([
        "audit", "--config", str(config), "--migrations", str(missing), "--quiet",
    ]) == 2

def test_demo_writes_six_self_contained_fixture_reports(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(ROOT)
    output = tmp_path / "demo"
    assert main(["demo", "--out", str(output)]) == 0
    summary = json.loads((output / "demo_summary.json").read_text(encoding="utf-8"))
    assert [item["name"] for item in summary["fixtures"]] == [
        "good", "risky", "conflict", "missing_down", "dialects", "exempted",
    ]
    for item in summary["fixtures"]:
        directory = output / item["name"]
        assert {"findings.json", "report.md", "report.html", "ledger.sqlite3"} <= {
            path.name for path in directory.iterdir()
        }
        assert "http" not in (directory / "report.html").read_text(encoding="utf-8").lower()
    risky_data = json.loads((output / "risky" / "findings.json").read_text(encoding="utf-8"))
    fk_findings = [
        item for item in risky_data["findings"]
        if item["rule_id"] == "rollback.foreign_key_order"
    ]
    assert fk_findings and fk_findings[0]["severity"] == "blocker"
    risky_pair = next(
        pair for pair in risky_data["rollback"]["pairs"] if pair["version"] == 7
    )
    assert risky_pair["foreign_key_order"]["edges"][0]["referenced_table"] == "demo_invoice_parent"
    index = (output / "index.html").read_text(encoding="utf-8").lower()
    assert "<script" not in index and "http://" not in index and "https://" not in index
