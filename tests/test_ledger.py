import sqlite3
from pathlib import Path
import yaml
from qianshen.audit import run_audit
from qianshen.config import load_config
from conftest import make_config, run_case
REQUIRED_TABLES = {
    "runs", "files", "statements", "findings", "rule_snapshots",
    "exemptions_applied", "diffs", "errors",
}
DROP_PAIR = {
    "0001_change.up.sql": "DROP TABLE IF EXISTS demo_x;",
    "0001_change.down.sql": "CREATE TABLE demo_x (id INT);",
}

def rows(ledger: Path, sql: str) -> list[sqlite3.Row]:
    connection = sqlite3.connect(ledger)
    connection.row_factory = sqlite3.Row
    try:
        return connection.execute(sql).fetchall()
    finally:
        connection.close()

def test_all_required_tables_are_written(tmp_path: Path):
    _, _, ledger = run_case(tmp_path, DROP_PAIR, tag="schema")
    names = {row["name"] for row in rows(ledger, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert REQUIRED_TABLES <= names
    run = rows(ledger, "SELECT * FROM runs")[0]
    assert run["project"] == "qianshen-audit"
    assert run["exit_code"] == 1 and run["blocking_count"] >= 1
    assert len(rows(ledger, "SELECT * FROM files")) == 2
    assert len(rows(ledger, "SELECT * FROM statements")) >= 2
    assert len(rows(ledger, "SELECT * FROM findings")) >= 2
    assert len(rows(ledger, "SELECT * FROM rule_snapshots")) >= 20

def test_exempted_findings_are_recorded_not_deleted(tmp_path: Path):
    exemptions = yaml.safe_dump({"exemptions": [{
        "id": "ex-ledger", "rule_id": "destructive.drop_table", "version": 1,
        "reason": "合成演示豁免", "expires_on": "2030-01-01",
    }]}, allow_unicode=True)
    outcome, _, ledger = run_case(
        tmp_path, DROP_PAIR, tag="exempt", exemptions_text=exemptions
    )
    assert len(outcome.exempted) == 1
    hit = rows(ledger, "SELECT * FROM exemptions_applied")[0]
    assert hit["exemption_id"] == "ex-ledger"
    stored = rows(ledger, "SELECT status, exemption_id FROM findings WHERE rule_id = 'destructive.drop_table'")[0]
    assert stored["status"] == "exempted" and stored["exemption_id"] == "ex-ledger"

def test_second_run_writes_diff_rows_against_previous_run(tmp_path: Path):
    files = {
        "0001_a.up.sql": "SELECT 1;",
        "0001_a.down.sql": "SELECT 1;",
    }
    config = load_config(make_config(tmp_path, files, tag="diff"))
    run_audit(config)
    (tmp_path / "migrations" / "0001_a.up.sql").write_text(
        "DROP TABLE IF EXISTS demo_x;", encoding="utf-8"
    )
    (tmp_path / "migrations" / "0001_a.down.sql").write_text(
        "CREATE TABLE demo_x (id INT);", encoding="utf-8"
    )
    second = run_audit(config)
    assert second.diff["baseline_available"] is True
    stored = rows(config.ledger_path, "SELECT category, rule_id FROM diffs ORDER BY category, rule_id")
    assert stored and {row["category"] for row in stored} == {"new"}

def test_parse_fallback_is_written_to_errors(tmp_path: Path):
    _, _, ledger = run_case(
        tmp_path, {"0001_broken.up.sql": "DROP TABLE demo_x 'unterminated;"}, tag="err"
    )
    errors = rows(ledger, "SELECT * FROM errors WHERE stage = 'parse'")
    assert errors and errors[0]["code"] == "parse_fallback"
    assert errors[0]["line"] == 1
