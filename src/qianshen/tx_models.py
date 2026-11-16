"""事务解释器数据结构：语句效果、逐语句事件与折叠后的事务段。"""
from __future__ import annotations
from dataclasses import dataclass, field
# 语句对当前打开事务的边界效果
KEEP = "keep"
COMMIT_BEFORE = "commit_before"
COMMIT_AFTER = "commit_after"
COMMIT_BOTH = "commit_both"
FORBIDDEN = "forbidden"
UNKNOWN = "unknown"
# 事务控制语句自身的边界标记
B_BEGIN, B_COMMIT, B_ROLLBACK = "explicit_begin", "explicit_commit", "explicit_rollback"
# 段关闭方式
C_EXPLICIT_COMMIT = "explicit_commit"
C_EXPLICIT_ROLLBACK = "explicit_rollback"
C_IMPLICIT = "implicit_commit"
C_NESTED_BEGIN = "nested_begin"
C_EOF = "eof_unclosed"
# 段状态
S_COMMITTED = "committed"
S_ROLLED_BACK = "rolled_back"
S_COMMITTED_UNPROVEN = "committed_boundary_unproven"
S_ROLLED_BACK_UNPROVEN = "rolled_back_boundary_unproven"
S_CUT = "implicit_commit_cut"
S_UNCLOSED = "unclosed"
S_UNCLOSED_UNPROVEN = "unclosed_boundary_unproven"

@dataclass(frozen=True)
class TxEffect:
    """单条语句在特定方言下的事务效果（能力表条目）。"""
    boundary: str
    rollbackable: bool | None
    allowed_in_transaction: bool
    confidence: str
    basis: str

@dataclass
class TxEvent:
    seq: int
    start_line: int
    end_line: int
    kind: str
    boundary: str
    rollbackable: bool | None
    allowed_in_transaction: bool
    confidence: str
    parse_ok: bool
    segment_index: int | None
    summary: str
    basis: str
    note: str = ""
    @property
    def source(self) -> str:
        return "ast" if self.parse_ok else "token"

@dataclass
class _Record:
    """带对象名的语句记录（变更/副作用/禁用语句共用）。"""
    seq: int
    start_line: int
    kind: str
    object_name: str
    summary: str
    parse_ok: bool
    reason: str = ""
    @property
    def source(self) -> str:
        return "ast" if self.parse_ok else "token"

# 三类记录共用同一结构，按用途区分；保留别名以表达语义。
ChangeRecord = SideEffectRecord = ForbiddenRecord = _Record

@dataclass
class TxSegment:
    """折叠后的一个有效事务段。"""
    index: int
    begin_seq: int
    begin_line: int
    close_seq: int | None = None
    close_line: int | None = None
    close_kind: str | None = None
    status: str = S_UNCLOSED
    proven: bool = True
    unknown_from_seq: int | None = None
    unknown_reason: str = ""
    cut_seq: int | None = None
    cut_line: int | None = None
    cut_summary: str | None = None
    cut_boundary: str | None = None
    committed_before_cut: list[_Record] = field(default_factory=list)
    changes_after_cut: list[_Record] = field(default_factory=list)
    side_effects: list[_Record] = field(default_factory=list)
    forbidden: list[_Record] = field(default_factory=list)
    pending: list[_Record] = field(default_factory=list)
    orphan_terminator_lines: list[int] = field(default_factory=list)

@dataclass
class TxInterpretation:
    dialect: str
    dialect_supported: bool
    events: list[TxEvent] = field(default_factory=list)
    segments: list[TxSegment] = field(default_factory=list)
    autocommitted_changes: list[_Record] = field(default_factory=list)
    orphan_terminators: list[TxEvent] = field(default_factory=list)
