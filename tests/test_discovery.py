from pathlib import Path
import pytest
from qianshen.config import load_config
from qianshen.discovery import detect_layout, discover
from qianshen.util import QianshenError, sha256_bytes
from conftest import make_config, write_files

def test_paired_discovery_metadata(tmp_path: Path):
    files = {
        "0001_base.up.sql": "CREATE TABLE demo_base (id INT);\n",
        "0001_base.down.sql": "DROP TABLE demo_base;\n",
    }
    outcome, errors = run_discovery(tmp_path, files)
    assert errors == []
    assert [item.rel_path for item in outcome] == ["0001_base.down.sql", "0001_base.up.sql"]
    up = next(item for item in outcome if item.direction == "up")
    assert (up.version, up.direction, up.description, up.line_count) == (1, "up", "base", 1)
    assert up.sha256 == sha256_bytes((tmp_path / "migrations" / "0001_base.up.sql").read_bytes())
    assert up.mtime_placeholder == "1970-01-01T00:00:00Z"

def run_discovery(tmp_path: Path, files: dict[str, str], **kwargs):
    config = load_config(make_config(tmp_path, files, **kwargs))
    return discover(config)

def test_single_file_mode(tmp_path: Path):
    found, errors = run_discovery(tmp_path, {"0001_single.sql": "SELECT 1;\n"})
    assert [(item.version, item.direction) for item in found] == [(1, "single")]
    assert detect_layout(found)["mode"] == "single"
    assert errors == []

def test_ignore_dirs_globs_and_paths(tmp_path: Path):
    files = {
        "0001_keep.up.sql": "SELECT 1;",
        "0001_keep.down.sql": "SELECT 1;",
        "0002_skip.tmp.sql": "SELECT 1;",
        "nested/0003_nested.up.sql": "SELECT 1;",
        "ignored_dir/0004_hidden.up.sql": "SELECT 1;",
    }
    found, _ = run_discovery(tmp_path, files, ignore={
        "dirs": ["ignored_dir"], "globs": ["*.tmp.sql"], "paths": ["nested"]
    })
    assert [item.rel_path for item in found] == ["0001_keep.down.sql", "0001_keep.up.sql"]

def test_invalid_name_is_recorded_without_aborting_scan(tmp_path: Path):
    found, errors = run_discovery(tmp_path, {
        "0001_ok.up.sql": "SELECT 1;", "0001_ok.down.sql": "SELECT 1;",
        "not_a_migration.sql": "not sql at all",
    })
    bad = next(item for item in found if item.rel_path == "not_a_migration.sql")
    assert bad.version is None and bad.direction == "unknown"
    assert "filename_does_not_match" in (bad.naming_error or "")
    assert errors == []

def test_mixed_layout_detected(tmp_path: Path):
    found, _ = run_discovery(tmp_path, {
        "0001_pair.up.sql": "SELECT 1;", "0001_pair.down.sql": "SELECT 1;",
        "0002_single.sql": "SELECT 1;",
    })
    assert detect_layout(found)["mode"] == "mixed"

def test_discovery_does_not_parse_sql(tmp_path: Path):
    broken = "this is not parseable ((( 'unterminated"
    found, errors = run_discovery(tmp_path, {
        "0001_broken.up.sql": broken, "0001_broken.down.sql": "SELECT 1;"
    })
    assert len(found) == 2 and errors == []
    assert found[1].sha256

def test_missing_directory_raises_controlled_error(tmp_path: Path):
    config = load_config(make_config(tmp_path, None))
    with pytest.raises(QianshenError) as exc:
        discover(config)
    assert exc.value.exit_code == 2

def test_width_mismatch_keeps_version_and_marks_error(tmp_path: Path):
    found, _ = run_discovery(tmp_path, {
        "00001_wide.up.sql": "SELECT 1;", "00001_wide.down.sql": "SELECT 1;"
    })
    assert found[0].version == 1
    assert "version_width" in (found[0].naming_error or "")
