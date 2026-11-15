from pathlib import Path
from qianshen.config import load_config
from qianshen.discovery import discover
from qianshen.rollback_pair import check_rollback_pairs
from qianshen.sql_parse import parse_all
from conftest import make_config

def rollback(tmp_path: Path, files: dict[str, str], *, tag: str = "rb", **kwargs):
    config = load_config(make_config(tmp_path, files, tag=tag, **kwargs))
    found, _ = discover(config)
    statements, _ = parse_all(found, config.dialect)
    return check_rollback_pairs(found, statements, config)

def rule_ids(findings) -> set[str]:
    return {item.rule_id for item in findings}

def pair_files(up: str, down: str) -> dict[str, str]:
    return {"0001_change.up.sql": up, "0001_change.down.sql": down}

def test_matching_pair_is_ok(tmp_path: Path):
    findings, result = rollback(tmp_path, pair_files(
        "CREATE TABLE IF NOT EXISTS demo_x (id INT);", "DROP TABLE IF EXISTS demo_x;"
    ))
    assert findings == []
    assert result["pairs"][0]["status"] == "ok"
    assert result["pairs"][0]["evidence_source"] == "ast"

def test_missing_down(tmp_path: Path):
    findings, result = rollback(tmp_path, {"0001_change.up.sql": "SELECT 1;"})
    assert "rollback.missing_down" in rule_ids(findings)
    assert result["pairs"][0]["status"] == "missing_down"

def test_empty_down(tmp_path: Path):
    findings, result = rollback(tmp_path, pair_files(
        "CREATE TABLE IF NOT EXISTS demo_x (id INT);", "-- nothing here\n"
    ))
    assert "rollback.empty_down" in rule_ids(findings)
    assert result["pairs"][0]["status"] == "empty_down"

def test_object_mismatch_and_extra_down_object(tmp_path: Path):
    findings, result = rollback(tmp_path, pair_files(
        "CREATE TABLE IF NOT EXISTS demo_x (id INT); CREATE INDEX IF NOT EXISTS idx_x ON demo_x(id);",
        "DROP INDEX IF EXISTS idx_other;",
    ))
    assert {"rollback.object_mismatch", "rollback.down_extra_object"} <= rule_ids(findings)
    assert result["pairs"][0]["missing_objects"]
    assert result["pairs"][0]["extra_objects"]

def test_approved_irreversible_marker_classifies_without_hiding(tmp_path: Path):
    findings, result = rollback(tmp_path, pair_files(
        '-- qianshen: irreversible approved-reason="demo fixture"\nDROP TABLE IF EXISTS demo_x;',
        "CREATE TABLE demo_x (id INT);",
    ))
    assert "rollback.irreversible_unapproved" not in rule_ids(findings)
    changes = result["pairs"][0]["irreversible_changes"]
    assert changes and changes[0]["approved"] is True

def test_unapproved_irreversible_change(tmp_path: Path):
    findings, result = rollback(tmp_path, pair_files(
        "DROP TABLE IF EXISTS demo_x;", "CREATE TABLE demo_x (id INT);"
    ))
    assert "rollback.irreversible_unapproved" in rule_ids(findings)
    assert result["pairs"][0]["status"] == "irreversible"

def test_destructive_operation_in_down(tmp_path: Path):
    findings, _ = rollback(tmp_path, pair_files(
        "CREATE TABLE IF NOT EXISTS demo_x (id INT);", "TRUNCATE TABLE demo_other;"
    ))
    assert "rollback.destructive_in_down" in rule_ids(findings)

def test_token_fallback_evidence_source_and_downgrade(tmp_path: Path):
    findings, result = rollback(tmp_path, pair_files(
        "DROP TABLE demo_x 'unterminated;", "CREATE TABLE demo_x (id INT);"
    ))
    assert result["pairs"][0]["evidence_source"] == "token"
    finding = next(item for item in findings if item.rule_id == "rollback.irreversible_unapproved")
    assert finding.source == "token" and finding.severity == "warning"

def test_single_mode_skips_pairing_with_notice(tmp_path: Path):
    findings, result = rollback(tmp_path, {"0001_single.sql": "CREATE TABLE demo_x (id INT);"})
    assert findings == []
    assert result["notices"] and "单文件" in result["notices"][0]

def test_pairing_can_be_disabled(tmp_path: Path):
    findings, result = rollback(tmp_path, pair_files(
        "DROP TABLE IF EXISTS demo_x;", "CREATE TABLE demo_x (id INT);"
    ), pairing={"check_rollback": False})
    assert findings == [] and result["enabled"] is False

def test_pair_report_carries_foreign_key_order_section(tmp_path: Path):
    _, result = rollback(tmp_path, pair_files(
        "CREATE TABLE IF NOT EXISTS demo_x (id INT);", "DROP TABLE IF EXISTS demo_x;"
    ))
    section = result["pairs"][0]["foreign_key_order"]
    assert section["version"] == 1 and section["status"] == "ok"
    assert section["edges"] == [] and section["unconfirmed"] == []
    assert section["order_findings"] == [] and section["unconfirmed_findings"] == []

def test_foreign_key_blocker_flows_through_pair_findings_and_status(tmp_path: Path):
    findings, result = rollback(tmp_path, {
        "0001_fk.up.sql": (
            "CREATE TABLE parent (id INT PRIMARY KEY);\n"
            "CREATE TABLE child (id INT, pid INT REFERENCES parent(id));\n"
        ),
        "0001_fk.down.sql": "DROP TABLE parent;\nDROP TABLE child;\n",
    })
    blocker = next(item for item in findings if item.rule_id == "rollback.foreign_key_order")
    pair = result["pairs"][0]
    assert pair["status"] == "foreign_key_order"
    assert blocker.fingerprint in pair["foreign_key_order"]["order_findings"]
    edge = pair["foreign_key_order"]["edges"][0]
    assert set(edge) == {
        "constraint", "source_table", "referenced_table",
        "defined_file", "defined_seq", "live",
    }
