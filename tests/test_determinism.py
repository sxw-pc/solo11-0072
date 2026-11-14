import sqlite3
from pathlib import Path
from qianshen.audit import run_audit
from qianshen.config import load_config
from conftest import make_config
FILES = {
    "0001_change.up.sql": "DROP TABLE IF EXISTS demo_x; UPDATE demo_x SET a = 1;",
    "0001_change.down.sql": "CREATE TABLE demo_x (id INT);",
}

def test_repeated_run_produces_byte_identical_reports(tmp_path: Path):
    config = load_config(make_config(tmp_path, FILES, tag="repeat"))
    first = run_audit(config)
    snapshot = {
        name: (config.output_dir / name).read_bytes()
        for name in ("findings.json", "report.md", "report.html")
    }
    second = run_audit(config)
    assert first.run_id == second.run_id
    assert first.exit_code == second.exit_code == 1
    for name, content in snapshot.items():
        assert (config.output_dir / name).read_bytes() == content, name
    connection = sqlite3.connect(config.ledger_path)
    try:
        stats = connection.execute("SELECT COUNT(*), COUNT(DISTINCT run_id) FROM runs").fetchone()
    finally:
        connection.close()
    assert stats == (2, 1)

def test_injected_clock_is_used_everywhere(tmp_path: Path):
    config_path = make_config(tmp_path, FILES, tag="clock", clock="2031-05-06T07:08:09Z")
    outcome = run_audit(load_config(config_path))
    assert outcome.started_at == "2031-05-06T07:08:09Z"
    assert outcome.ended_at == outcome.started_at
    assert outcome.started_at in (config_path.parent / "out_clock" / "report.md").read_text(encoding="utf-8")
