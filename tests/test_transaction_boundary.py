"""方言事务能力表、有效事务段与提交边界 finding 的专项测试。"""
from pathlib import Path
from qianshen.config import load_config
from qianshen.discovery import discover
from qianshen.models import FileInfo
from qianshen.rules_engine import evaluate_rules, load_rules
from qianshen.sql_parse import parse_all, parse_file
from qianshen.tx_interpreter import interpret_transactions
from qianshen.util import sha256_text
from conftest import make_config

SCENARIO = ("BEGIN; UPDATE queue SET status='x' WHERE id=1; "
            "ALTER TABLE jobs ADD COLUMN c INT; UPDATE jobs SET c=1 WHERE id=1; ROLLBACK;")

def _file(sql: str) -> FileInfo:
    return FileInfo(path=Path("f.up.sql"), rel_path="f.up.sql", version=1, version_raw="1",
                    description="d", direction="up", size_bytes=1, line_count=1,
                    sha256=sha256_text(sql), mtime_placeholder="x", text=sql)

def _segments(sql: str, dialect: str):
    return interpret_transactions(dialect, parse_file(_file(sql), dialect)[0]).segments

def _findings(tmp_path, sql: str, dialect: str):
    config = load_config(make_config(tmp_path, {"0001_x.up.sql": sql}, tag="tx", dialect=dialect))
    files, _ = discover(config)
    stmts, _ = parse_all(files, config.dialect)
    return {f.rule_id: f for f in evaluate_rules(load_rules(config), files, stmts, config)}

def test_postgres_alter_is_fully_rollbackable():
    segs = _segments(SCENARIO, "postgres")
    assert len(segs) == 1 and segs[0].status == "rolled_back" and segs[0].proven
    assert segs[0].cut_seq is None and segs[0].committed_before_cut == []

def test_mysql_alter_cuts_transaction_before_and_after():
    segs = _segments(SCENARIO, "mysql")
    cut = next(s for s in segs if s.status == "implicit_commit_cut")
    assert [c.kind for c in cut.committed_before_cut] == ["update", "alter_table_add_column"]
    assert cut.committed_before_cut[0].object_name == "queue"
    tail = next(s for s in segs if s.status == "rolled_back")
    assert tail.index == cut.index + 1  # 末段 ROLLBACK 撤不回已提交的前段

def test_mysql_cut_enters_blocker_gate_but_postgres_does_not(tmp_path):
    assert "transaction.implicit_commit_cut" in _findings(tmp_path, SCENARIO, "mysql")
    assert "transaction.implicit_commit_cut" not in _findings(tmp_path, SCENARIO, "postgres")
    # 普通同事务混合 DDL/DML 检查在两种方言下都保留，不被新结果覆盖
    for d in ("mysql", "postgres"):
        assert "availability.ddl_dml_in_transaction" in _findings(tmp_path, SCENARIO, d)

def test_mysql_temporary_table_side_effect_survives_rollback_without_cut():
    sql = "BEGIN; UPDATE queue SET id=1 WHERE id=1; CREATE TEMPORARY TABLE stage (id INT); ROLLBACK;"
    segs = _segments(sql, "mysql")
    assert segs[0].status == "rolled_back" and segs[0].cut_seq is None
    assert [e.kind for e in segs[0].side_effects] == ["create_table"]
    assert segs[0].side_effects[0].object_name == "stage"
    # Postgres 临时表可回滚，没有该副作用
    assert _segments(sql, "postgres")[0].side_effects == []

def test_temporary_flag_preserved_in_token_fallback():
    stmt = parse_file(_file("CREATE TEMPORARY TABLE stage (id INT OOPS OOPS"), "mysql")[0][0]
    assert stmt.parse_ok is False and stmt.kind == "create_table"
    assert stmt.attrs.get("temporary") is True

def test_multiple_cut_points_each_get_own_segment():
    sql = ("BEGIN; UPDATE a SET x=1 WHERE id=1; ALTER TABLE b ADD COLUMN c INT; "
           "UPDATE b SET c=1 WHERE id=1; DROP TABLE d; UPDATE e SET y=2 WHERE id=1; ROLLBACK;")
    cuts = [s for s in _segments(sql, "mysql") if s.status == "implicit_commit_cut"]
    assert len(cuts) == 2
    assert [c.object_name for c in cuts[0].committed_before_cut][-1] == "b"
    assert [c.object_name for c in cuts[1].committed_before_cut] == ["b", "d"]

def test_nested_begin_and_unclosed_and_orphan_handled():
    nested = _segments("BEGIN; UPDATE a SET x=1 WHERE id=1; BEGIN; UPDATE b SET y=2 WHERE id=1; COMMIT;", "mysql")
    assert nested[0].status == "implicit_commit_cut" and nested[0].close_kind == "nested_begin"
    assert [c.kind for c in nested[0].committed_before_cut] == ["update"]
    unclosed = _segments("BEGIN; UPDATE a SET x=1 WHERE id=1;", "postgres")
    assert unclosed[0].close_kind == "eof_unclosed" and unclosed[0].status == "unclosed"

def test_unknown_statement_marks_boundary_unproven_not_atomic(tmp_path):
    sql = "BEGIN; UPDATE a SET x=1 WHERE id=1; VACUUM FULL a; UPDATE a SET y=2 WHERE id=1; ROLLBACK;"
    segs = _segments(sql, "postgres")
    assert segs[0].proven is False and segs[0].unknown_from_seq is not None
    assert segs[0].status == "rolled_back_boundary_unproven"
    finding = _findings(tmp_path, sql, "postgres")["transaction.boundary_unknown"]
    assert finding.confidence == "low"

def test_postgres_concurrently_forbidden_in_transaction(tmp_path):
    sql = "BEGIN; CREATE INDEX CONCURRENTLY idx ON t(a); COMMIT;"
    finding = _findings(tmp_path, sql, "postgres")["transaction.forbidden_in_transaction"]
    assert finding.severity == "blocker"

def test_no_explicit_transaction_produces_no_tx_finding(tmp_path):
    tx = {k for k in _findings(tmp_path, "UPDATE a SET x=1 WHERE id=1; ALTER TABLE b ADD COLUMN c INT;", "mysql")
          if k.startswith("transaction.")}
    assert tx == set()
