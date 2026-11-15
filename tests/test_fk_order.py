"""外键依赖顺序审查的针对性测试：阻断发现、跨版本生命周期与保守降级。"""
from pathlib import Path
from qianshen.config import load_config
from qianshen.discovery import discover
from qianshen.rollback_pair import check_rollback_pairs
from qianshen.sql_parse import parse_all
from conftest import make_config

ORDER = "rollback.foreign_key_order"
UNCONFIRMED = "rollback.foreign_key_unconfirmed"


def run(tmp_path: Path, files: dict[str, str], tag: str = "fk", **kwargs):
    config = load_config(make_config(tmp_path, files, tag=tag, **kwargs))
    found, _ = discover(config)
    statements, _ = parse_all(found, config.dialect)
    return check_rollback_pairs(found, statements, config)


def rule_map(findings) -> dict[str, list]:
    result: dict[str, list] = {}
    for item in findings:
        result.setdefault(item.rule_id, []).append(item)
    return result


def pair_v1(result) -> dict:
    return result["pairs"][0]["foreign_key_order"]


def test_parent_child_same_version_correct_order_is_ok(tmp_path: Path):
    findings, result = run(tmp_path, {
        "0001_fk.up.sql": (
            "CREATE TABLE parent (id INT PRIMARY KEY);\n"
            "CREATE TABLE child (id INT, pid INT REFERENCES parent(id));\n"
        ),
        "0001_fk.down.sql": "DROP TABLE child;\nDROP TABLE parent;\n",
    })
    assert rule_map(findings).get(ORDER, []) == []
    assert result["pairs"][0]["status"] == "ok"
    edge = pair_v1(result)["edges"][0]
    assert edge["source_table"] == "child" and edge["referenced_table"] == "parent"
    assert edge["defined_file"].endswith("up.sql") and edge["live"] is True


def test_reversed_down_emits_blocker_with_edge_and_two_positions(tmp_path: Path):
    findings, result = run(tmp_path, {
        "0001_fk.up.sql": (
            "CREATE TABLE parent (id INT PRIMARY KEY);\n"
            "CREATE TABLE child (id INT, pid INT REFERENCES parent(id));\n"
        ),
        "0001_fk.down.sql": "DROP TABLE parent;\nDROP TABLE child;\n",
    })
    blocked = rule_map(findings)[ORDER]
    assert len(blocked) == 1 and blocked[0].severity == "blocker"
    finding = blocked[0]
    assert finding.direction == "down" and finding.statement_seq == 1
    assert "child -> parent" in finding.evidence
    assert "0001_fk.down.sql:1" in finding.evidence
    assert result["pairs"][0]["status"] == "foreign_key_order"
    assert finding.fingerprint in pair_v1(result)["order_findings"]


def test_up_child_before_parent_is_blocked_at_child_statement(tmp_path: Path):
    findings, _ = run(tmp_path, {
        "0001_fk.up.sql": (
            "CREATE TABLE child (id INT, pid INT REFERENCES parent(id));\n"
            "CREATE TABLE parent (id INT PRIMARY KEY);\n"
        ),
        "0001_fk.down.sql": "DROP TABLE child;\nDROP TABLE parent;\n",
    })
    blocked = rule_map(findings)[ORDER]
    assert len(blocked) == 1
    assert blocked[0].direction == "up" and blocked[0].statement_seq == 1
    assert "parent" in blocked[0].evidence


def test_alter_table_fk_has_same_ordering_semantics(tmp_path: Path):
    findings, result = run(tmp_path, {
        "0001_fk.up.sql": (
            "CREATE TABLE parent (id INT PRIMARY KEY);\n"
            "CREATE TABLE child (id INT, pid INT);\n"
            "ALTER TABLE child ADD CONSTRAINT fk_cp "
            "FOREIGN KEY (pid) REFERENCES parent(id);\n"
        ),
        "0001_fk.down.sql": (
            "ALTER TABLE child DROP CONSTRAINT fk_cp;\n"
            "DROP TABLE child;\nDROP TABLE parent;\n"
        ),
    })
    assert ORDER not in rule_map(findings)
    assert result["pairs"][0]["status"] == "ok"
    edge = pair_v1(result)["edges"][0]
    assert edge["constraint"] == "fk_cp" and edge["referenced_table"] == "parent"


def test_alter_fk_reversed_down_is_blocked(tmp_path: Path):
    findings, _ = run(tmp_path, {
        "0001_fk.up.sql": (
            "CREATE TABLE parent (id INT PRIMARY KEY);\n"
            "CREATE TABLE child (id INT, pid INT);\n"
            "ALTER TABLE child ADD CONSTRAINT fk_cp "
            "FOREIGN KEY (pid) REFERENCES parent(id);\n"
        ),
        "0001_fk.down.sql": "DROP TABLE parent;\nDROP TABLE child;\n",
    })
    blocked = rule_map(findings)[ORDER]
    assert len(blocked) == 1 and blocked[0].detail.startswith("down-order:child->parent:fk_cp")


def test_fk_dropped_in_later_version_does_not_block_earlier_parent_drop(tmp_path: Path):
    findings, result = run(tmp_path, {
        "0001_a.up.sql": (
            "CREATE TABLE parent (id INT PRIMARY KEY);\n"
            "CREATE TABLE child (id INT, pid INT, "
            "CONSTRAINT fk1 FOREIGN KEY (pid) REFERENCES parent(id));\n"
        ),
        "0001_a.down.sql": "DROP TABLE child;\nDROP TABLE parent;\n",
        "0002_b.up.sql": "ALTER TABLE child DROP CONSTRAINT fk1;\n",
        "0002_b.down.sql": (
            "ALTER TABLE child ADD CONSTRAINT fk1 "
            "FOREIGN KEY (pid) REFERENCES parent(id);\n"
        ),
    })
    assert ORDER not in rule_map(findings)
    by_version = {pair["version"]: pair for pair in result["pairs"]}
    assert by_version[1]["foreign_key_order"]["status"] == "ok"
    assert by_version[2]["foreign_key_order"]["status"] == "ok"


def test_self_reference_and_unrelated_table_do_not_block(tmp_path: Path):
    findings, result = run(tmp_path, {
        "0001_fk.up.sql": (
            "CREATE TABLE node (id INT PRIMARY KEY, parent_id INT REFERENCES node(id));\n"
            "CREATE TABLE lone (id INT);\n"
        ),
        "0001_fk.down.sql": "DROP TABLE node;\nDROP TABLE lone;\n",
    })
    assert ORDER not in rule_map(findings)
    assert UNCONFIRMED not in rule_map(findings)
    assert result["pairs"][0]["status"] == "ok"


def test_multi_table_drop_in_one_statement_is_unconfirmed_not_passed(tmp_path: Path):
    findings, _ = run(tmp_path, {
        "0001_fk.up.sql": (
            "CREATE TABLE parent (id INT PRIMARY KEY);\n"
            "CREATE TABLE child (id INT, pid INT REFERENCES parent(id));\n"
        ),
        "0001_fk.down.sql": "DROP TABLE child, parent;\n",
    })
    notes = rule_map(findings)[UNCONFIRMED]
    assert notes and all(item.severity == "warning" for item in notes)
    assert any("child" in item.evidence and "parent" in item.evidence for item in notes)
    assert ORDER not in rule_map(findings)


def test_rename_table_reports_unconfirmed_dependency(tmp_path: Path):
    findings, _ = run(tmp_path, {
        "0001_fk.up.sql": (
            "CREATE TABLE parent (id INT PRIMARY KEY);\n"
            "CREATE TABLE child (id INT, pid INT REFERENCES parent(id));\n"
            "ALTER TABLE child RENAME TO child_v2;\n"
        ),
        "0001_fk.down.sql": (
            "ALTER TABLE child_v2 RENAME TO child;\n"
            "DROP TABLE child;\nDROP TABLE parent;\n"
        ),
    })
    notes = rule_map(findings)[UNCONFIRMED]
    assert notes and any("改名" in item.evidence for item in notes)
    assert ORDER not in rule_map(findings)


def test_cross_version_parent_is_unconfirmed_instead_of_blocker(tmp_path: Path):
    findings, result = run(tmp_path, {
        "0001_a.up.sql": "CREATE TABLE parent (id INT PRIMARY KEY);\n",
        "0001_a.down.sql": "DROP TABLE parent;\n",
        "0002_b.up.sql": "CREATE TABLE child (id INT, pid INT REFERENCES parent(id));\n",
        "0002_b.down.sql": "DROP TABLE child;\n",
    })
    assert ORDER not in rule_map(findings)
    notes = rule_map(findings)[UNCONFIRMED]
    assert len(notes) == 1 and notes[0].version == 2
    assert result["pairs"][1]["foreign_key_order"]["status"] == "foreign_key_unconfirmed"


def test_unparseable_down_reports_unconfirmed_with_low_confidence(tmp_path: Path):
    findings, _ = run(tmp_path, {
        "0001_fk.up.sql": (
            "CREATE TABLE parent (id INT PRIMARY KEY);\n"
            "CREATE TABLE child (id INT, pid INT REFERENCES parent(id));\n"
        ),
        "0001_fk.down.sql": "DROP TABLE parent 'unterminated;",
    })
    notes = rule_map(findings)[UNCONFIRMED]
    assert notes and notes[0].confidence == "low" and notes[0].source == "token"
    assert notes[0].severity == "info"  # warning 经 token 来源降级
    assert ORDER not in rule_map(findings)


def test_unknown_parent_table_is_blocked_not_silently_accepted(tmp_path: Path):
    findings, _ = run(tmp_path, {
        "0001_fk.up.sql": "CREATE TABLE child (id INT, pid INT REFERENCES ghost(id));\n",
        "0001_fk.down.sql": "DROP TABLE child;\n",
    })
    blocked = rule_map(findings)[ORDER]
    assert len(blocked) == 1 and "ghost" in blocked[0].evidence
