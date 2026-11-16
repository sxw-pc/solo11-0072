from pathlib import Path
import yaml
from qianshen.config import load_config
from qianshen.discovery import discover
from qianshen.version_chain import check_version_chain
from conftest import make_config

def chain(tmp_path: Path, files: dict[str, str], **kwargs):
    config = load_config(make_config(tmp_path, files, **kwargs))
    found, _ = discover(config)
    return check_version_chain(found, config)

def ids(findings) -> set[str]:
    return {item.rule_id for item in findings}

def test_duplicate_version_and_direction(tmp_path: Path):
    findings, result = chain(tmp_path, {
        "0001_a.up.sql": "SELECT 1;", "0001_a.down.sql": "SELECT 1;",
        "0001_b.up.sql": "SELECT 1;", "0001_b.down.sql": "SELECT 1;",
    })
    assert "version.duplicate" in ids(findings)
    assert result["drift"]["duplicates"] == 2

def test_version_gap(tmp_path: Path):
    findings, result = chain(tmp_path, {
        "0001_a.up.sql": "SELECT 1;", "0001_a.down.sql": "SELECT 1;",
        "0004_b.up.sql": "SELECT 1;", "0004_b.down.sql": "SELECT 1;",
    })
    gap = next(item for item in findings if item.rule_id == "version.gap")
    assert "0002-0003" in gap.evidence and result["drift"]["gaps"] == 1

def test_mixed_layout_and_invalid_name(tmp_path: Path):
    findings, _ = chain(tmp_path, {
        "0001_a.up.sql": "SELECT 1;", "0001_a.down.sql": "SELECT 1;",
        "0002_b.sql": "SELECT 1;", "bad.sql": "SELECT 1;",
    })
    assert {"version.mixed_layout", "version.invalid_name"} <= ids(findings)

def test_width_and_lexicographic_order(tmp_path: Path):
    findings, _ = chain(tmp_path, {
        "0001_a.up.sql": "SELECT 1;", "0001_a.down.sql": "SELECT 1;",
        "00002_b.up.sql": "SELECT 1;", "00002_b.down.sql": "SELECT 1;",
    })
    assert {"version.naming_width", "version.out_of_order"} <= ids(findings)

def test_missing_direction(tmp_path: Path):
    findings, _ = chain(tmp_path, {"0001_only.up.sql": "SELECT 1;"})
    assert "version.missing_direction" in ids(findings)

def test_baseline_modified_deleted_added(tmp_path: Path):
    files = {
        "0001_a.up.sql": "SELECT 1;", "0001_a.down.sql": "SELECT 1;",
        "0002_b.up.sql": "SELECT 2;", "0002_b.down.sql": "SELECT 2;",
    }
    config = load_config(make_config(tmp_path, files, tag="base"))
    found, _ = discover(config)
    baseline = {"files": [
        {"path": item.rel_path, "sha256": item.sha256, "version": item.version,
         "direction": item.direction} for item in found
    ]}
    (tmp_path / "migrations" / "0001_a.up.sql").write_text("SELECT 999;", encoding="utf-8")
    (tmp_path / "migrations" / "0002_b.down.sql").unlink()
    (tmp_path / "migrations" / "0003_c.up.sql").write_text("SELECT 3;", encoding="utf-8")
    findings, result = chain(
        tmp_path, None, tag="drift", baseline_text=yaml.safe_dump(baseline),
    )
    rule_ids = ids(findings)
    assert {"baseline.file_modified", "baseline.file_deleted", "baseline.file_added"} <= rule_ids
    assert result["baseline"]["counts"] == {"modified": 1, "deleted": 1, "added": 1}

def test_manifest_is_deterministic_and_ordered(tmp_path: Path):
    files = {
        "0002_b.up.sql": "SELECT 2;", "0001_a.up.sql": "SELECT 1;",
        "0001_a.down.sql": "SELECT 1;", "0002_b.down.sql": "SELECT 2;",
    }
    _, first = chain(tmp_path, files, tag="one")
    _, second = chain(tmp_path, files, tag="two")
    assert first["manifest"] == second["manifest"]
    assert first["manifest_sha256"] == second["manifest_sha256"]

def test_version_chain_works_when_sql_is_unparseable(tmp_path: Path):
    findings, _ = chain(tmp_path, {
        "0001_a.up.sql": "not sql 'unterminated", "0001_a.down.sql": "SELECT 1;",
        "0001_b.up.sql": "SELECT 1;",
    })
    assert "version.duplicate" in ids(findings)
