from pathlib import Path
import yaml
from qianshen.config import load_config
from qianshen.discovery import discover
from qianshen.rules_engine import evaluate_rules, load_rules
from qianshen.sql_parse import parse_all
from qianshen.util import finding_sort_key
from conftest import make_config, run_case

def evaluate(tmp_path: Path, files: dict[str, str], *, tag: str = "r", **kwargs):
    config = load_config(make_config(tmp_path, files, tag=tag, **kwargs))
    found, _ = discover(config)
    statements, _ = parse_all(found, config.dialect)
    return evaluate_rules(load_rules(config), found, statements, config)

def rule_ids(findings) -> set[str]:
    return {item.rule_id for item in findings}

def test_drop_table_is_blocker(tmp_path: Path):
    findings = evaluate(tmp_path, {"0001_drop.up.sql": "DROP TABLE IF EXISTS demo_x;"})
    finding = next(item for item in findings if item.rule_id == "destructive.drop_table")
    assert finding.severity == "blocker" and finding.confidence == "high"

def test_update_and_delete_without_where(tmp_path: Path):
    findings = evaluate(tmp_path, {
        "0001_dml.up.sql": "UPDATE demo_x SET a = 1; DELETE FROM demo_x;"
    })
    assert {"dml.update_without_where", "dml.delete_without_where"} <= rule_ids(findings)

def test_delete_with_where_is_not_flagged(tmp_path: Path):
    findings = evaluate(tmp_path, {
        "0001_dml.up.sql": "DELETE FROM demo_x WHERE id = 1;"
    })
    assert "dml.delete_without_where" not in rule_ids(findings)

def test_not_null_without_default_but_backfill_suppresses(tmp_path: Path):
    no_backfill = evaluate(tmp_path, {
        "0001_nn.up.sql": "ALTER TABLE demo_x ADD COLUMN note VARCHAR(20) NOT NULL;"
    }, tag="a")
    with_backfill = evaluate(tmp_path, {
        "0001_nn.up.sql": (
            "ALTER TABLE demo_x ADD COLUMN note VARCHAR(20) NOT NULL;"
            "UPDATE demo_x SET note = 'backfilled';"
        )
    }, tag="b")
    assert "schema.add_not_null_without_default" in rule_ids(no_backfill)
    assert "schema.add_not_null_without_default" not in rule_ids(with_backfill)

def test_type_narrowing_cross_file(tmp_path: Path):
    findings = evaluate(tmp_path, {
        "0001_base.up.sql": "CREATE TABLE demo_x (id INT, label VARCHAR(80));",
        "0002_change.up.sql": "ALTER TABLE demo_x ALTER COLUMN label TYPE VARCHAR(12);",
    })
    assert "schema.type_narrowing" in rule_ids(findings)

def test_permissions_allowed_by_config(tmp_path: Path):
    files = {"0001_grant.up.sql": "GRANT SELECT ON demo_x TO demo_reader;"}
    blocked = evaluate(tmp_path, files, tag="deny")
    allowed = evaluate(
        tmp_path, files, tag="allow", permissions={"allow_grants": True}
    )
    assert "permissions.grant_revoke_not_allowed" in rule_ids(blocked)
    assert "permissions.grant_revoke_not_allowed" not in rule_ids(allowed)

def test_rule_override_severity_and_disable(tmp_path: Path):
    files = {"0001_drop.up.sql": "DROP TABLE IF EXISTS demo_x;"}
    overridden = evaluate(
        tmp_path, files, tag="sev",
        rule_overrides={"destructive.drop_table": {"severity": "info"}},
    )
    disabled = evaluate(
        tmp_path, files, tag="off",
        rule_overrides={"destructive.drop_table": {"enabled": False}},
    )
    assert next(item for item in overridden if item.rule_id == "destructive.drop_table").severity == "info"
    assert "destructive.drop_table" not in rule_ids(disabled)

def test_rule_dialect_direction_and_path_scope(tmp_path: Path):
    rules = {
        "rules": [{
            "id": "custom.drop", "title": "drop", "severity": "warning",
            "category": "custom", "applies_to": ["statement"],
            "match": {"kind": ["drop_table"]}, "message": "drop", "suggestion": "x",
            "enabled": True, "directions": ["up"], "dialects": ["postgres"],
            "path_globs": ["0001_*"],
        }]
    }
    files = {
        "0001_drop.up.sql": "DROP TABLE IF EXISTS demo_a;",
        "0002_drop.up.sql": "DROP TABLE IF EXISTS demo_b;",
        "0001_drop.down.sql": "DROP TABLE IF EXISTS demo_c;",
    }
    findings = evaluate(tmp_path, files, tag="scope", rules_text=yaml.safe_dump(rules))
    assert [item.file for item in findings if item.rule_id == "custom.drop"] == ["0001_drop.up.sql"]
    mysql = evaluate(
        tmp_path, files, tag="mysql", rules_text=yaml.safe_dump(rules), dialect="mysql"
    )
    assert not [item for item in mysql if item.rule_id == "custom.drop"]

def test_token_fallback_downgrades_confidence(tmp_path: Path):
    findings = evaluate(tmp_path, {
        "0001_broken.up.sql": "DROP TABLE demo_x 'unterminated;"
    })
    finding = next(item for item in findings if item.rule_id == "destructive.drop_table")
    assert finding.source == "token" and finding.severity == "warning"
    assert finding.confidence == "low"

def test_findings_sort_and_fingerprint_stability(tmp_path: Path):
    files = {
        "0001_alert.up.sql": "DROP TABLE IF EXISTS demo_x; UPDATE demo_x SET a = 1;",
        "0001_alert.down.sql": "SELECT 1;",
    }
    first, _, _ = run_case(tmp_path, files, tag="one")
    shifted = {
        "0001_alert.up.sql": "\n\n" + files["0001_alert.up.sql"],
        "0001_alert.down.sql": files["0001_alert.down.sql"],
    }
    second, _, _ = run_case(tmp_path, shifted, tag="two")
    active = list(first.active_findings)
    assert active == sorted(first.active_findings, key=finding_sort_key)
    assert active[0].severity == "blocker"
    first_fp = {(item.rule_id, item.fingerprint) for item in first.active_findings}
    second_fp = {(item.rule_id, item.fingerprint) for item in second.active_findings}
    assert first_fp == second_fp
