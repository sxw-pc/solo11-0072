from pathlib import Path
from qianshen.models import FileInfo
from qianshen.sql_parse import parse_all, parse_file, parse_statement, split_sql
from qianshen.util import sha256_text

def make_file(sql: str, *, name: str = "0001_demo.up.sql", version: int = 1, direction: str = "up") -> FileInfo:
    return FileInfo(
        path=Path(name), rel_path=name, version=version, version_raw=str(version),
        description="demo", direction=direction, size_bytes=len(sql.encode()),
        line_count=len(sql.splitlines()), sha256=sha256_text(sql),
        mtime_placeholder="1970-01-01T00:00:00Z", text=sql,
    )

def first(sql: str, dialect: str = "postgres"):
    statements, warnings = parse_file(make_file(sql), dialect)
    return statements[0], warnings

def test_statement_split_respects_strings_comments_and_lines():
    sql = "-- header\nSELECT ';' AS x;\n/* block */\nUPDATE demo_t SET a = 1;\n"
    parts = split_sql(sql)
    assert len(parts) == 2
    assert parts[0][1:] == (2, 2)
    assert parts[1][1:] == (4, 4)

def test_create_table_columns_and_if_not_exists():
    statement, warnings = first(
        "CREATE TABLE IF NOT EXISTS demo_t (id INT PRIMARY KEY, name VARCHAR(20) NOT NULL DEFAULT 'x');"
    )
    assert statement.kind == "create_table" and warnings == []
    assert statement.attrs["if_not_exists"] is True
    columns = {item["name"]: item for item in statement.attrs["columns"]}
    assert columns["name"]["not_null"] is True and columns["name"]["has_default"] is True

def test_alter_actions_are_extracted():
    statement, _ = first("ALTER TABLE demo_t ADD COLUMN note VARCHAR(30) NOT NULL;")
    assert statement.actions == ["add_column"]
    assert statement.attrs["added_columns"][0]["not_null"] is True
    assert statement.attrs["has_if_not_exists"] is False

def test_dml_where_detection_and_objects():
    update, _ = first("UPDATE demo_t SET a = 1;")
    delete, _ = first("DELETE FROM demo_t WHERE id > 0;")
    assert update.kind == "update" and update.attrs["has_where"] is False
    assert delete.kind == "delete" and delete.attrs["has_where"] is True
    assert update.objects == ["demo_t"] and delete.objects == ["demo_t"]

def test_drop_truncate_grant_and_transaction_classification():
    kinds = [
        first("DROP TABLE demo_t;")[0].kind,
        first("TRUNCATE TABLE demo_t;")[0].kind,
        first("GRANT SELECT ON demo_t TO demo_reader;")[0].kind,
        first("BEGIN;")[0].kind,
        first("COMMIT;")[0].kind,
    ]
    assert kinds == ["drop_table", "truncate", "grant", "begin", "commit"]

def test_unparseable_sql_uses_conservative_token_fallback():
    statement, warnings = first("UPDATE demo_t SET a = 'unterminated;")
    assert statement.parse_ok is False and statement.source == "token"
    assert statement.kind == "update"
    assert warnings and warnings[0]["code"] == "parse_fallback"

def test_summary_is_truncated():
    statement, _ = first("UPDATE demo_t SET note = '" + "x" * 500 + "' WHERE id = 1;")
    assert len(statement.summary) <= 180
    assert "x" * 300 not in statement.summary

def test_three_dialects_parse_declared_forms():
    cases = {
        "postgres": "CREATE TABLE demo_pg (id INTEGER PRIMARY KEY, label TEXT);",
        "mysql": "CREATE TABLE demo_my (id INT AUTO_INCREMENT PRIMARY KEY) ENGINE=InnoDB;",
        "sqlite": "CREATE TABLE demo_sq (id INTEGER PRIMARY KEY AUTOINCREMENT);",
    }
    for dialect, sql in cases.items():
        statement, _ = first(sql, dialect)
        assert statement.kind == "create_table", dialect
        assert statement.file_rel == "0001_demo.up.sql"

def test_type_narrowing_is_annotated_across_versions():
    first_file = make_file(
        "CREATE TABLE demo_t (id INT, name VARCHAR(80));", name="0001_base.up.sql", version=1
    )
    second_file = make_file(
        "ALTER TABLE demo_t ALTER COLUMN name TYPE VARCHAR(20);",
        name="0002_narrow.up.sql", version=2,
    )
    statements, _ = parse_all([first_file, second_file], "postgres")
    alter = next(item for item in statements if item.kind == "alter_table_alter_type")
    assert alter.attrs["type_change"] == "narrowing"

def test_comments_only_produces_no_statements():
    statements, warnings = parse_file(make_file("-- only a comment\n/* and another */\n"), "postgres")
    assert statements == [] and warnings == []

def test_invalid_shape_falls_back_without_raising():
    statement = parse_statement(
        "CREATE TABLE demo_broken (id INTEGER OOPS OOPS", seq=1, start_line=1,
        end_line=1, file=make_file("x"), dialect="postgres",
    )
    assert statement.parse_ok is False
    assert statement.parse_warning

def test_create_table_extracts_inline_and_table_level_foreign_keys():
    statement, _ = first(
        "CREATE TABLE child (id INT, pid INT REFERENCES parent(id), "
        "CONSTRAINT fk_c FOREIGN KEY (pid) REFERENCES parent(id));"
    )
    edges = statement.attrs["foreign_keys"]
    assert [edge["referenced_table"] for edge in edges] == ["parent", "parent"]
    inline, named = edges
    assert inline["named"] is False and inline["source_table"] == "child"
    assert inline["constraint"].startswith("__anon_fk_")
    assert inline["defined_in"] == "inline_reference"
    assert named["constraint"] == "fk_c" and named["named"] is True
    assert named["columns"] == ["pid"]
    assert named["defined_in"] == "table_constraint"

def test_alter_table_extracts_add_and_drop_constraint_lists():
    added, _ = first(
        "ALTER TABLE child ADD CONSTRAINT fk_cp "
        "FOREIGN KEY (pid) REFERENCES parent(id) ON DELETE CASCADE;"
    )
    assert added.actions == ["add_constraint"]
    edge = added.attrs["foreign_keys"][0]
    assert edge["constraint"] == "fk_cp"
    assert edge["source_table"] == "child" and edge["referenced_table"] == "parent"
    assert edge["defined_in"] == "add_constraint"
    dropped, _ = first("ALTER TABLE child DROP CONSTRAINT fk_cp;")
    assert dropped.attrs["dropped_constraints"] == ["fk_cp"]
    assert dropped.attrs["dropped_constraint"] == "fk_cp"  # 旧标量字段保持兼容

def test_alter_table_multi_action_is_flagged_and_constraints_kept():
    statement, _ = first(
        "ALTER TABLE child DROP CONSTRAINT fk_old, "
        "ADD CONSTRAINT fk_new FOREIGN KEY (a) REFERENCES p2(id);"
    )
    assert statement.attrs["multi_action"] is True
    assert statement.attrs["dropped_constraints"] == ["fk_old"]
    assert statement.attrs["foreign_keys"][0]["constraint"] == "fk_new"

def test_self_referencing_foreign_key_is_extracted():
    statement, _ = first(
        "CREATE TABLE node (id INT PRIMARY KEY, parent_id INT REFERENCES node(id));"
    )
    edge = statement.attrs["foreign_keys"][0]
    assert edge["source_table"] == "node" and edge["referenced_table"] == "node"
