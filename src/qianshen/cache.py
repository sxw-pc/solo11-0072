"""本地解析缓存与类型状态检查点。

缓存分两层，各自拥有独立的失效边界：

- 解析层（ParseCache）：只保存与文件字节直接相关的中性解析事实
  （split_sql 分句结果、sqlglot 方言分类、保守 token 回退标记）。
  条目身份 = 原始文件 SHA-256 + 方言 + sqlglot 解析器版本 + 缓存格式版本。
  命中后由调用方以本轮 FileInfo 重新绑定路径、版本、方向与文件哈希。

- 类型状态层（StateCache）：为每个有序迁移保存入态/出态检查点。
  记录键 = (文件内容身份, 入态摘要)，命中时必须核对完整规范化入态、
  排序键与语句形态；任何一项不一致都不得复用，只能向后重算。

规则、豁免、历史 diff 与报告生成永远不进入缓存。缓存不可用、损坏、
版本不兼容或读写失败时，所有操作透明退回全量计算路径。
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any
import sqlglot
from .models import FileInfo
from .util import canonical_json, ensure_dir, sha256_text
PARSE_CACHE_FORMAT_VERSION = 1
STATE_CACHE_FORMAT_VERSION = 1
_PARSE_FORMAT_TAG = "qianshen-parse-cache"
_STATE_FORMAT_TAG = "qianshen-state-cache"
_MAX_STATE_RECORDS = 4096

def parser_version() -> str:
    """SQL 解析器版本；解析行为变化必须使全部解析事实失效。"""
    return str(getattr(sqlglot, "__version__", "unknown"))

def parse_identity(file_sha256: str, dialect: str) -> str:
    """文件解析事实的完整身份：内容 + 方言 + 解析器版本 + 缓存格式版本。"""
    return canonical_json([
        _PARSE_FORMAT_TAG, PARSE_CACHE_FORMAT_VERSION,
        parser_version(), dialect, file_sha256,
    ])

def canonical_state(state: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """规范化类型状态：{表: {列: 类型描述}} 的排序副本，用于可比较的身份。

    状态身份必须覆盖被追踪对象的完整限定身份与列类型描述；仅比较文件
    SHA 或摘要字符串不足以证明两轮运行的类型推演输入一致。
    """
    canonical: dict[str, dict[str, Any]] = {}
    for table in sorted(state):
        columns = state[table]
        if not isinstance(columns, dict):
            raise TypeError("类型状态的列映射必须是字典")
        canonical[str(table)] = {str(col): columns[col] for col in sorted(columns)}
    return canonical

def state_digest(state: dict[str, dict[str, Any]]) -> str:
    return sha256_text(canonical_json(canonical_state(state)))

def _atomic_write_json(path: Path, payload: Any) -> None:
    """临时文件 + os.replace 原子落盘；失败时清理半成品。"""
    ensure_dir(path.parent)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temp.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True),
            encoding="utf-8", newline="\n",
        )
        os.replace(temp, path)
    finally:
        try:
            temp.unlink()
        except OSError:
            pass

class ParseCache:
    """按文件内容身份缓存中性解析结果；每个条目一个 JSON 文件。"""
    def __init__(self, directory: Path, dialect: str) -> None:
        self._dir = directory
        self._dialect = dialect

    def _path_for(self, file_sha256: str) -> Path:
        return self._dir / f"{sha256_text(parse_identity(file_sha256, self._dialect))}.json"

    def load(self, file: FileInfo) -> dict[str, Any] | None:
        """读取并校验条目；任何不一致都返回 None（按未命中处理）。"""
        try:
            payload = json.loads(self._path_for(file.sha256).read_text(encoding="utf-8"))
            checks = (
                isinstance(payload, dict)
                and payload.get("format") == _PARSE_FORMAT_TAG
                and payload.get("format_version") == PARSE_CACHE_FORMAT_VERSION
                and payload.get("parser_version") == parser_version()
                and payload.get("dialect") == self._dialect
                and payload.get("file_sha256") == file.sha256
                and payload.get("text_sha256") == sha256_text(file.text)
                and isinstance(payload.get("statements"), list)
            )
            return payload if checks else None
        except (OSError, ValueError):
            return None

    def store(self, file: FileInfo, statements_payload: list[dict[str, Any]]) -> None:
        """尽力而为地写入；只读目录、并发冲突等失败一律静默忽略。"""
        try:
            _atomic_write_json(self._path_for(file.sha256), {
                "format": _PARSE_FORMAT_TAG,
                "format_version": PARSE_CACHE_FORMAT_VERSION,
                "parser_version": parser_version(),
                "dialect": self._dialect,
                "file_sha256": file.sha256,
                "text_sha256": sha256_text(file.text),
                "statements": statements_payload,
            })
        except (OSError, TypeError, ValueError):
            pass

class StateCache:
    """每文件入态/出态检查点；按 (方言, 解析器版本) 分栈共存。"""
    def __init__(self, path: Path, dialect: str) -> None:
        self._path = path
        self._stack_key = f"{dialect}|{parser_version()}"
        self._other_stacks: dict[str, Any] = {}
        self._records: dict[tuple[str, str], dict[str, Any]] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
            valid = (
                isinstance(payload, dict)
                and payload.get("format") == _STATE_FORMAT_TAG
                and payload.get("format_version") == STATE_CACHE_FORMAT_VERSION
                and isinstance(payload.get("stacks"), dict)
            )
            stacks = payload["stacks"] if valid else {}
            for key, value in stacks.items():
                if key != self._stack_key:
                    self._other_stacks[key] = value
            records = stacks.get(self._stack_key) or []
            for record in records if isinstance(records, list) else []:
                if isinstance(record, dict) and isinstance(record.get("file_sha256"), str) \
                        and isinstance(record.get("in_state_digest"), str):
                    self._records[(record["file_sha256"], record["in_state_digest"])] = record
        except (OSError, ValueError, AttributeError):
            self._other_stacks, self._records = {}, {}

    def lookup(self, file_sha256: str, in_state_digest: str) -> dict[str, Any] | None:
        return self._records.get((file_sha256, in_state_digest))

    def store(self, record: dict[str, Any]) -> None:
        key = (record["file_sha256"], record["in_state_digest"])
        if self._records.get(key) != record:
            self._records[key] = record
            self._dirty = True

    def flush(self) -> None:
        """原子写回；失败不阻断审计，也不留下可被误命中的半成品。"""
        if not self._dirty:
            return
        try:
            records = list(self._records.values())[-_MAX_STATE_RECORDS:]
            stacks = dict(self._other_stacks, **{self._stack_key: records})
            _atomic_write_json(self._path, {
                "format": _STATE_FORMAT_TAG,
                "format_version": STATE_CACHE_FORMAT_VERSION,
                "stacks": stacks,
            })
            self._dirty = False
        except (OSError, TypeError, ValueError):
            pass

class AuditCache:
    """解析缓存与类型状态检查点的组合门面；所有操作均为尽力而为。"""
    def __init__(self, cache_dir: Path, dialect: str) -> None:
        self.parse = ParseCache(cache_dir / "parse", dialect)
        self.state = StateCache(cache_dir / "state.json", dialect)

    @classmethod
    def open(cls, config: Any) -> "AuditCache | None":
        """缓存被禁用或无法初始化时返回 None，调用方走全量计算路径。"""
        try:
            if not getattr(config, "cache_enabled", False):
                return None
            return cls(Path(config.cache_dir), config.dialect)
        except Exception:
            return None

    def flush(self) -> None:
        self.state.flush()
