"""两层本地缓存。ParseCache 只存与文件 SHA+方言+sqlglot+格式版本绑定的
中性解析事实（路线 B），type_change 等跨文件结论永不入缓存；
StateCheckpointCache 按解析身份+文件位置+语句序+完整入态保存检查点，
不满足任一条件即毒化重算到链末端。IO/损坏/版本问题透明降级，原子写入。
"""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
from typing import Any
import sqlglot
from .type_compare import (
    TypeStateEngine, canonicalize_state, ordered_file_groups,
)
from .util import canonical_json, sha256_text
SQLGLOT_VERSION = sqlglot.__version__
PARSE_CACHE_FORMAT = 1   # 分句/AST 中性事实载荷版本
STATE_CACHE_FORMAT = 1   # 类型状态检查点载荷版本
# annotate 阶段写入、依赖跨文件 schema 状态的 attrs 键；永不进入解析缓存。
TYPE_ANNOTATION_KEYS = ("type_change", "type_changes")
ALTER_ANNOTATION_KEYS = ("old_type", "relation")
def parser_identity() -> dict[str, str]:
    return {"sqlglot": SQLGLOT_VERSION, "parse_format": str(PARSE_CACHE_FORMAT),
            "state_format": str(STATE_CACHE_FORMAT)}
def _safe_read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temp.write_text(content, encoding="utf-8", newline="\n")
        os.replace(temp, path)
    except OSError:
        try:
            temp.unlink()
        except OSError:
            pass
        raise
def _shard(cache_dir: Path, namespace: str, key: str) -> Path:
    return cache_dir / namespace / key[:2] / f"{key}.json"
def _digest(payload: dict[str, Any]) -> str:
    return sha256_text(canonical_json(
        {k: v for k, v in payload.items() if k != "entry_sha256"}))
def neutralize_attrs(attrs: dict[str, Any]) -> dict[str, Any]:
    """剥离跨文件类型标注，只留中性解析事实。"""
    clean = dict(attrs)
    for key in TYPE_ANNOTATION_KEYS:
        clean.pop(key, None)
    if isinstance(clean.get("type_alterations"), list):
        clean["type_alterations"] = [
            {k: v for k, v in item.items() if k not in ALTER_ANNOTATION_KEYS}
            if isinstance(item, dict) else item
            for item in clean["type_alterations"]]
    return clean
def _identity_matches(identity: dict[str, Any], *, state: bool = False) -> bool:
    key = "state_format" if state else "parse_format"
    return identity.get("sqlglot") == SQLGLOT_VERSION and identity.get(
        key) == int(parser_identity()[key])
class _Store:
    """可写性只探测一次；只读时静默跳过写入。"""
    namespace = ""
    def __init__(self, cache_dir: Path | None) -> None:
        self.cache_dir = cache_dir
        self.enabled = cache_dir is not None
        self.writable: bool | None = None if cache_dir is not None else False
        self.hits = self.misses = self.errors = 0
    def _path(self, key: str) -> Path:
        return _shard(self.cache_dir, self.namespace, key)  # type: ignore[arg-type]
    def ensure_writable(self) -> bool:
        if self.writable is not None:
            return self.writable
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)  # type: ignore[union-attr]
            probe = self.cache_dir / ".write-probe"  # type: ignore[union-attr]
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            self.writable = True
        except OSError:
            self.writable, self.errors = False, self.errors + 1
        return self.writable
    def _write(self, key: str, payload: dict[str, Any]) -> None:
        if not self.ensure_writable():
            return
        payload["entry_sha256"] = _digest(payload)
        try:
            _atomic_write(self._path(key), canonical_json(payload))
        except OSError:
            self.errors, self.writable = self.errors + 1, False
    def _fetch(self, key: str, valid: Any) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        payload = _safe_read(self._path(key))
        if not valid(payload):
            self.misses += 1
            return None
        self.hits += 1
        return payload
class ParseCache(_Store):
    """文件级中性解析事实缓存。"""
    namespace = "parse"
    @staticmethod
    def entry_key(file_sha256: str, dialect: str) -> str:
        env = parser_identity()
        return sha256_text(canonical_json({
            "file_sha256": file_sha256, "dialect": dialect,
            "sqlglot": env["sqlglot"], "parse_format": env["parse_format"]}))
    def get(self, key: str, file_sha256: str, dialect: str) -> dict[str, Any] | None:
        return self._fetch(key, lambda p: self._valid(p, key, file_sha256, dialect))
    def put(self, key: str, *, file_sha256: str, dialect: str,
            statements: list[dict[str, Any]]) -> None:
        if not self.enabled:
            return
        env = parser_identity()
        self._write(key, {
            "identity": {"file_sha256": file_sha256, "dialect": dialect,
                         "sqlglot": env["sqlglot"], "parse_format": int(env["parse_format"])},
            "statements": statements})
    def _valid(self, payload: Any, key: str, file_sha256: str, dialect: str) -> bool:
        if not isinstance(payload, dict) or not isinstance(payload.get("identity"), dict):
            return False
        identity = payload["identity"]
        if identity.get("file_sha256") != file_sha256 or identity.get("dialect") != dialect:
            return False
        if not _identity_matches(identity) or payload.get("entry_sha256") != _digest(payload):
            return False
        if not isinstance(payload.get("statements"), list):
            return False
        if key != self.entry_key(file_sha256, dialect):
            return False
        for item in payload["statements"]:
            attrs = item.get("attrs") if isinstance(item, dict) else None
            if not isinstance(attrs, dict) or any(k in attrs for k in TYPE_ANNOTATION_KEYS):
                return False
            if any(isinstance(a, dict) and any(k in a for k in ALTER_ANNOTATION_KEYS)
                   for a in attrs.get("type_alterations", [])):
                return False
        return True
def state_identity(*, parse_key: str, rel_path: str, version: int | None,
                   direction: str, seq_fingerprint: str, state_in: Any) -> dict[str, Any]:
    env = parser_identity()
    return {"parse_key": parse_key, "rel_path": rel_path, "version": version,
            "direction": direction, "seq_fingerprint": seq_fingerprint,
            "state_in": state_in, "sqlglot": env["sqlglot"],
            "state_format": int(env["state_format"])}
class StateCheckpointCache(_Store):
    """逐文件完整入态/出态快照与标注增量。"""
    namespace = "state"
    def entry_key(self, **kwargs: Any) -> str:
        return sha256_text(canonical_json(state_identity(**kwargs)))
    def get(self, key: str, **kwargs: Any) -> dict[str, Any] | None:
        return self._fetch(key, lambda p: self._valid(p, key, kwargs))
    def put(self, key: str, *, state_out: Any, annotations: list[dict[str, Any]],
            **kwargs: Any) -> None:
        if self.enabled:
            self._write(key, {"identity": state_identity(**kwargs),
                              "state_out": state_out, "annotations": annotations})
    def _valid(self, payload: Any, key: str, kwargs: dict[str, Any]) -> bool:
        if not isinstance(payload, dict) or not isinstance(payload.get("identity"), dict):
            return False
        identity = payload["identity"]
        if not _identity_matches(identity, state=True) or identity != state_identity(**kwargs):
            return False
        if payload.get("entry_sha256") != _digest(payload):
            return False
        if "state_out" not in payload or not isinstance(payload.get("annotations"), list):
            return False
        return key == self.entry_key(**kwargs)
def annotate_with_checkpoints(statements: list[Any], parse_key_of: Any,
                              cache: StateCheckpointCache) -> tuple[int, int]:
    """全量顺序推演；完整入态命中才复用，否则重算并向后传播至链末端。"""
    engine = TypeStateEngine()
    hits = misses = 0
    for (version, rel_path), group in ordered_file_groups(statements):
        if any(not s.parse_ok for s in group):
            engine.poisoned = True  # token fallback 可能隐藏状态变更
        kwargs = {"parse_key": parse_key_of(rel_path), "rel_path": rel_path, "version": version,
                  "direction": group[0].direction,
                  "seq_fingerprint": sha256_text(canonical_json([[s.seq, s.sha256] for s in group])),
                  "state_in": engine.snapshot_in()}
        payload = (cache.get(cache.entry_key(**kwargs), **kwargs)
                   if cache.enabled and not engine.poisoned else None)
        if payload is not None:
            saved_state = copy.deepcopy(engine.state)
            engine.replay_file(group, payload.get("annotations", []))
            if not engine.poisoned and canonicalize_state(engine.state) == payload["state_out"]:
                hits += 1
                continue
            engine.state, engine.poisoned = saved_state, True  # 出态不符：拒绝复用
            cache.errors += 1
        misses += 1
        annotations = engine.apply_file(group)
        if cache.enabled and not engine.poisoned:
            cache.put(cache.entry_key(**kwargs), state_out=canonicalize_state(engine.state),
                      annotations=annotations, **kwargs)
    return hits, misses
