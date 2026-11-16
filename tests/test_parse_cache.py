"""两层本地缓存的身份边界、增量收敛与容错测试。"""
from __future__ import annotations
import json
import os
from dataclasses import replace
from pathlib import Path
import qianshen.parse_cache as pc
from qianshen.parse_cache import ParseCache, neutralize_attrs
from qianshen.sql_parse import CacheStats, parse_all, parse_file
from qianshen.util import sha256_text
from tests.test_sql_parse import make_file


def _chain():
    return [
        make_file("CREATE TABLE accounts (id INT, balance DECIMAL(12,2));",
                  name="0001_base.up.sql", version=1),
        make_file("ALTER TABLE accounts ALTER COLUMN balance TYPE DECIMAL(8,2);",
                  name="0007_narrow.up.sql", version=7),
        make_file("ALTER TABLE accounts ALTER COLUMN balance TYPE DECIMAL(20,2);",
                  name="0009_widen.up.sql", version=9),
    ]


def _relations(statements):
    return [[c["relation"] for c in s.attrs["type_changes"]]
            for s in statements if "type_changes" in s.attrs]


def _run(files, cache, dialect="postgres"):
    stats = CacheStats(cache is not None, str(cache) if cache else None)
    statements, _ = parse_all(files, dialect, cache_dir=cache, stats=stats)
    return statements, stats


def test_warm_run_skips_parse_and_state_and_matches_cold_run(tmp_path):
    cache = tmp_path / "cache"
    cold, _ = _run(_chain(), None)
    first, _ = _run(_chain(), cache)
    third, stats = _run(_chain(), cache)
    assert stats.parse_hits == 3 and stats.state_hits == 3 and stats.io_errors == 0
    assert _relations(third) == _relations(cold)
    assert [s.to_dict() for s in third] == [s.to_dict() for s in first]


def test_predecessor_schema_change_invalidates_state_but_keeps_parse(tmp_path):
    cache = tmp_path / "cache"
    _run(_chain(), cache)  # 预热
    new_text = "CREATE TABLE accounts (id INT, balance DECIMAL(4,2));"
    base = _chain()[0]
    changed = [replace(base, text=new_text, sha256=sha256_text(new_text)), *_chain()[1:]]
    statements, stats = _run(changed, cache)
    alter = next(s for s in statements if s.file_rel == "0007_narrow.up.sql")
    assert alter.attrs["type_changes"][0]["relation"] == "widening"  # 同字节 0007 结论改变
    assert stats.parse_hits == 2 and stats.parse_misses == 1  # 文本未变仍命中解析缓存
    assert stats.state_misses >= 2  # 入态改变，检查点失效重算
    _, stats2 = _run(changed, cache)
    assert stats2.state_hits == 3 and stats2.state_misses == 0  # 状态重新收敛


def test_dialect_change_never_shares_parse_entries(tmp_path):
    cache = tmp_path / "cache"
    _run(_chain(), cache)
    _, stats = _run(_chain(), cache, "mysql")
    assert stats.parse_hits == 0 and stats.parse_misses == 3
    assert ParseCache.entry_key("x", "postgres") != ParseCache.entry_key("x", "mysql")


def test_rename_rebinds_path_and_never_reuses_path_bound_state(tmp_path):
    cache = tmp_path / "cache"
    files = _chain()
    _run(files, cache)
    renamed = [replace(files[0], rel_path="9999_renamed.up.sql")] + files[1:]
    statements, stats = _run(renamed, cache)
    rebound = next(s for s in statements if s.file_rel == "9999_renamed.up.sql")
    assert rebound.file_sha256 == files[0].sha256  # FileInfo 重新绑定
    assert stats.parse_hits == 3 and stats.state_misses >= 1


def test_parser_version_bump_invalidates_entries(tmp_path):
    cache = tmp_path / "cache"
    _run(_chain(), cache)
    original = pc.SQLGLOT_VERSION
    pc.SQLGLOT_VERSION = "99.99.99"
    try:
        _, stats = _run(_chain(), cache)
        assert stats.parse_misses == 3 and stats.parse_hits == 0
    finally:
        pc.SQLGLOT_VERSION = original


def test_corrupted_and_forged_entries_fall_back_safely(tmp_path):
    cache = tmp_path / "cache"
    _run(_chain(), cache)
    next((cache / "parse").rglob("*.json")).write_text("{broken", encoding="utf-8")
    statements, _ = _run(_chain(), cache)  # 损坏：透明重算
    assert len(statements) == 3
    _run(_chain(), cache)  # 重建后伪造带类型标注的条目（连 digest 一起伪造）
    entry = next((cache / "parse").rglob("*.json"))
    payload = json.loads(entry.read_text())
    payload["statements"][0]["attrs"]["type_change"] = "narrowing"
    payload["entry_sha256"] = pc._digest(payload)
    entry.write_text(json.dumps(payload), encoding="utf-8")
    assert "type_change" not in neutralize_attrs(payload["statements"][0]["attrs"])
    again, _ = _run(_chain(), cache)
    assert all("type_change" not in s.attrs for s in again) or _relations(again)


def test_readonly_cache_dir_never_blocks_audit(tmp_path):
    ro = tmp_path / "ro"
    ro.mkdir()
    os.chmod(ro, 0o500)
    try:
        statements, stats = _run(_chain(), ro)
        assert len(statements) == 3 and stats.io_errors >= 1
        assert not list(ro.rglob("*.json"))  # 没有半成品落盘
    finally:
        os.chmod(ro, 0o700)


def test_cache_disabled_equivalent_to_full_chain(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    warm, _ = _run(_chain(), cache)
    cold, _ = _run(_chain(), None)  # cache_dir=None 走全链 annotate
    assert [s.to_dict() for s in warm] == [s.to_dict() for s in cold]
    monkeypatch.setenv("QIANSHEN_CACHE", "off")
    from qianshen.config import load_config
    cfg_path = tmp_path / "q.yml"
    cfg_path.write_text(
        f"migrations_dir: {tmp_path}\ndialect: postgres\nrules_file: /workspace/rules/default.yml\n"
        f"output_dir: {tmp_path / 'out'}\nledger_path: {tmp_path / 'l.db'}\n",
        encoding="utf-8")
    assert load_config(cfg_path).cache_enabled is False


def test_neutral_cache_payload_never_carries_type_annotations(tmp_path):
    cache = tmp_path / "cache"
    parse_file(make_file("ALTER TABLE accounts ALTER COLUMN balance TYPE DECIMAL(8,2);"),
               "postgres", ParseCache(cache))
    payload = json.loads(next((cache / "parse").rglob("*.json")).read_text())
    for item in payload["statements"]:
        assert not {"type_change", "type_changes"} & item["attrs"].keys()
        for alteration in item["attrs"].get("type_alterations", []):
            assert not {"old_type", "relation"} & alteration.keys()
