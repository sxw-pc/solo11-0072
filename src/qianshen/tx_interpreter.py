"""把文件的 StatementInfo 序列折叠成带真实提交边界的事务段。

未知策略：保留逐语句轨迹，仅把当前从事务首个 unknown 效果标记为“边界未证”，
此前可证明片段照常输出；未知段只在显式边界/可证明隐式提交/文件结束时终止，
绝不因读到 COMMIT/ROLLBACK 就把未知前段重写成已证明原子。
"""
from __future__ import annotations
from .models import StatementInfo
from .tx_capabilities import NESTED_BEGIN, dialect_supported, statement_effect
from .tx_models import (
    B_BEGIN, B_COMMIT, B_ROLLBACK, C_EOF, C_EXPLICIT_COMMIT, C_EXPLICIT_ROLLBACK,
    C_IMPLICIT, C_NESTED_BEGIN, COMMIT_BEFORE, COMMIT_BOTH, FORBIDDEN, KEEP, UNKNOWN,
    S_COMMITTED, S_COMMITTED_UNPROVEN, S_CUT, S_ROLLED_BACK, S_ROLLED_BACK_UNPROVEN,
    S_UNCLOSED, S_UNCLOSED_UNPROVEN, TxEvent, TxInterpretation, TxSegment, _Record,
)

def _object_name(stmt: StatementInfo) -> str:
    table = str(stmt.attrs.get("table") or "")
    if table: return table
    for key in ("dropped_constraint", "securable", "type", "index"):
        if stmt.attrs.get(key): return str(stmt.attrs[key])
    return stmt.objects[0] if stmt.objects else stmt.file_rel

def _record(stmt: StatementInfo, reason: str = "") -> _Record:
    return _Record(stmt.seq, stmt.start_line, stmt.kind, _object_name(stmt),
                   stmt.summary, stmt.parse_ok, reason)

class _Interpreter:
    def __init__(self, dialect: str) -> None:
        self.dialect = dialect
        self.result = TxInterpretation(dialect, dialect_supported(dialect))
        self._segment: TxSegment | None = None

    def _event(self, stmt: StatementInfo, boundary: str, *, rollbackable=None,
               allowed=True, confidence="high", basis="", note="") -> None:
        self.result.events.append(TxEvent(
            stmt.seq, stmt.start_line, stmt.end_line, stmt.kind, boundary,
            rollbackable, allowed, confidence, stmt.parse_ok,
            self._segment.index if self._segment else None,
            stmt.summary, basis, note,
        ))

    def _open(self, stmt: StatementInfo) -> TxSegment:
        segment = TxSegment(len(self.result.segments), stmt.seq, stmt.start_line)
        self.result.segments.append(segment)
        self._segment = segment
        return segment

    def _mark_unknown(self, stmt: StatementInfo, basis: str) -> None:
        segment = self._segment
        assert segment is not None
        if segment.proven:
            segment.proven, segment.unknown_from_seq, segment.unknown_reason = False, stmt.seq, basis

    def _close(self, stmt: StatementInfo | None, close_kind: str, status: str) -> None:
        segment = self._segment
        assert segment is not None
        segment.close_kind, segment.status = close_kind, status
        if stmt is not None: segment.close_seq, segment.close_line = stmt.seq, stmt.start_line
        self._segment = None

    def _implicit_cut(self, stmt: StatementInfo, boundary: str, basis: str, rollbackable: bool | None) -> None:
        segment = self._segment
        assert segment is not None
        segment.cut_seq, segment.cut_line = stmt.seq, stmt.start_line
        segment.cut_summary, segment.cut_boundary = stmt.summary, boundary
        # 只有未知点之前的待提交变更才能证明被该隐式提交带走。
        if segment.unknown_from_seq is None:
            segment.committed_before_cut = list(segment.pending)
        else:
            segment.committed_before_cut = [
                item for item in segment.pending if item.seq < segment.unknown_from_seq
            ]
        segment.pending.clear()
        if rollbackable is False: segment.side_effects.append(_record(stmt, basis))
        self._close(stmt, C_IMPLICIT, S_CUT)
        # DDL 执行后原事务边界已经结束；后续语句进入新的待提交段，
        # 直到下一个显式 BEGIN/隐式提交/显式结束，从而为多次切断点各自保留归属。
        reopened = TxSegment(len(self.result.segments), stmt.seq, stmt.start_line)
        reopened.cut_seq, reopened.cut_line = stmt.seq, stmt.start_line
        reopened.cut_summary, reopened.cut_boundary = stmt.summary, boundary
        reopened.status, reopened.close_kind = S_CUT, C_IMPLICIT
        self.result.segments.append(reopened); self._segment = reopened

    def _begin(self, stmt: StatementInfo) -> None:
        keyword = str(stmt.attrs.get("transaction_keyword") or "begin")
        if self._segment is None:
            self._event(stmt, B_BEGIN, note=keyword)
            self._open(stmt)
            return
        boundary, basis = NESTED_BEGIN.get(self.dialect, (UNKNOWN, "目标方言不支持，嵌套 BEGIN 效果未知"))
        if boundary == COMMIT_BEFORE:
            self._event(stmt, COMMIT_BEFORE, basis=basis, note=f"nested_begin:{keyword}")
            nested = self._segment
            nested.cut_seq, nested.cut_line = stmt.seq, stmt.start_line
            nested.cut_summary, nested.cut_boundary = stmt.summary, COMMIT_BEFORE
            nested.committed_before_cut = list(nested.pending)
            nested.pending.clear()
            self._close(stmt, C_NESTED_BEGIN, S_CUT)
            self._open(stmt)
        elif boundary == FORBIDDEN:
            self._event(stmt, FORBIDDEN, allowed=False, basis=basis, note="nested_begin")
            self._segment.forbidden.append(_record(stmt, basis))
        else:
            self._event(stmt, KEEP, basis=basis, note="nested_begin_ignored")

    def _terminator(self, stmt: StatementInfo) -> None:
        boundary = B_COMMIT if stmt.kind == "commit" else B_ROLLBACK
        if self._segment is None:
            self._event(stmt, boundary, note="orphan_terminator")
            self.result.orphan_terminators.append(TxEvent(
                stmt.seq, stmt.start_line, stmt.end_line, stmt.kind, boundary, None, True,
                "high", stmt.parse_ok, None, stmt.summary, "", "orphan_terminator"))
            # 没有打开事务的 ROLLBACK/COMMIT 撤回不了此前任何已提交段。
            for prior in self.result.segments:
                prior.orphan_terminator_lines.append(stmt.start_line)
            return
        self._event(stmt, boundary)
        if stmt.kind == "commit":
            status = S_COMMITTED if self._segment.proven else S_COMMITTED_UNPROVEN
            self._close(stmt, C_EXPLICIT_COMMIT, status)
        else:
            # ROLLBACK 只能撤回当前段内待提交变更；已被隐式提交的前段不受影响。
            status = S_ROLLED_BACK if self._segment.proven else S_ROLLED_BACK_UNPROVEN
            self._close(stmt, C_EXPLICIT_ROLLBACK, status)

    def _effective(self, stmt: StatementInfo) -> None:
        effect = statement_effect(self.dialect, stmt)
        self._event(
            stmt, effect.boundary, rollbackable=effect.rollbackable,
            allowed=effect.allowed_in_transaction, confidence=effect.confidence,
            basis=effect.basis,
        )
        if self._segment is None:
            if stmt.is_ddl or stmt.is_dml: self.result.autocommitted_changes.append(_record(stmt))
            return
        segment = self._segment
        changing = stmt.is_ddl or stmt.is_dml
        if effect.boundary == UNKNOWN:
            self._mark_unknown(stmt, effect.basis)
            if changing: segment.pending.append(_record(stmt))
        elif effect.boundary == FORBIDDEN:
            segment.forbidden.append(_record(stmt, effect.basis))
            if changing: segment.pending.append(_record(stmt))
        elif effect.boundary in (COMMIT_BEFORE, COMMIT_BOTH):
            if changing: segment.pending.append(_record(stmt))
            self._implicit_cut(stmt, effect.boundary, effect.basis, effect.rollbackable)
        else:  # KEEP
            if changing: segment.pending.append(_record(stmt))
            if effect.rollbackable is False: segment.side_effects.append(_record(stmt, effect.basis))

    def feed(self, statements: list[StatementInfo]) -> TxInterpretation:
        for stmt in statements:
            if stmt.kind == "begin":
                self._begin(stmt)
            elif stmt.kind in ("commit", "rollback"):
                self._terminator(stmt)
            else:
                self._effective(stmt)
        if self._segment is not None:
            segment = self._segment
            segment.close_kind = C_EOF
            segment.status = S_UNCLOSED if segment.proven else S_UNCLOSED_UNPROVEN
            self._segment = None
        return self.result
def interpret_transactions(dialect: str, statements: list[StatementInfo]) -> TxInterpretation:
    """把一个文件内的语句序列折叠成带真实提交边界的事务段解释结果。"""
    return _Interpreter(dialect).feed(list(statements))
