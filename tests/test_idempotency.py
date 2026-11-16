from pathlib import Path
from qianshen.idempotency import calculate_idempotency
from qianshen.models import FileInfo
from qianshen.sql_parse import parse_file
from qianshen.util import sha256_text

def score(sql: str) -> dict:
    file = FileInfo(
        path=Path("0001_demo.up.sql"), rel_path="0001_demo.up.sql", version=1,
        version_raw="1", description="demo", direction="up", size_bytes=len(sql),
        line_count=len(sql.splitlines()), sha256=sha256_text(sql),
        mtime_placeholder="1970-01-01T00:00:00Z", text=sql,
    )
    statements, _ = parse_file(file, "postgres")
    return calculate_idempotency([file], statements)

def codes(result: dict) -> list[str]:
    return [reason["code"] for reason in result["files"][0]["reasons"]]

def test_clean_migration_scores_100():
    result = score("CREATE TABLE IF NOT EXISTS demo_x (id INT);")
    assert result["score"] == 100 and result["reason_counts"] == {}

def test_deductions_are_explained_and_deterministic():
    sql = (
        "CREATE TABLE demo_x (id INT);\nDROP TABLE demo_y;\n"
        "UPDATE demo_z SET a = 1;\nINSERT INTO demo_q (id, v) VALUES (1, 'x');"
    )
    result = score(sql)
    assert result["score"] == 40
    assert codes(result) == [
        "create_without_if_not_exists", "destructive_ddl", "drop_without_if_exists",
        "fixed_primary_key_insert", "no_transaction_boundary", "unconditional_dml",
    ]
    assert codes(score(sql)) == codes(result)

def test_transaction_boundary_removes_that_deduction():
    result = score("BEGIN; CREATE TABLE demo_x (id INT); UPDATE demo_x SET a = 1; COMMIT;")
    assert "no_transaction_boundary" not in codes(result)
    assert result["score"] == 80

def test_duplicate_definition_and_low_score_file():
    result = score("CREATE TABLE demo_x (id INT); CREATE TABLE demo_x (id INT);")
    assert "duplicate_object" in codes(result)
    assert result["score"] == 65
    assert result["low_score_files"] == [{"file": "0001_demo.up.sql", "score": 65}]
