"""把方言事务解释结果转成规则 Finding（证据沿解释器边界落地）。"""
from __future__ import annotations
from typing import Any, Callable
from .config import Config
from .models import FileInfo, Rule, StatementInfo
from .tx_interpreter import interpret_transactions
from .tx_models import C_EOF, C_NESTED_BEGIN, S_CUT, S_ROLLED_BACK, S_ROLLED_BACK_UNPROVEN
from .util import canonical_json

def _summary(records: list[Any]) -> str:
    return ", ".join(f"L{r.start_line} {r.kind.upper()} {r.object_name}" for r in records)

def _detail(seg: Any, later: list[Any] | None) -> str:
    """进入 finding 指纹的稳定结构细节：只用 seq/kind/object，不含物理行号。"""
    return canonical_json({
        "segment": seg.index, "status": seg.status, "proven": seg.proven,
        "unknown_from_seq": seg.unknown_from_seq, "cut_seq": seg.cut_seq,
        "committed_before_cut": [
            {"seq": r.seq, "kind": r.kind, "object": r.object_name}
            for r in seg.committed_before_cut],
        "changes_after_cut": [
            {"seq": r.seq, "kind": r.kind, "object": r.object_name}
            for r in (later or seg.changes_after_cut)],
        "side_effects": [
            {"seq": r.seq, "kind": r.kind, "object": r.object_name, "reason": r.reason}
            for r in seg.side_effects],
        "forbidden": [
            {"seq": r.seq, "kind": r.kind, "object": r.object_name, "reason": r.reason}
            for r in seg.forbidden],
    })

def _later(segments: list[Any], seg: Any) -> list[Any]:
    """切断点之后、下一个显式 BEGIN 之前所有已自动提交的对象。"""
    later: list[Any] = []
    for follow in segments[seg.index + 1:]:
        if follow.close_kind == C_NESTED_BEGIN or (
            follow.cut_line is None and follow.close_kind == "explicit_commit"
        ):
            break
        later.extend(follow.committed_before_cut)
        if follow.cut_line is None: break
    return later

def build_tx_findings(
    rule: Rule, file: FileInfo, statements: list[StatementInfo], config: Config,
    check: str, add: Callable[..., None],
) -> None:
    interp = interpret_transactions(config.dialect, statements)
    by_seq = {s.seq: s for s in statements}

    def emit(anchor_seq, obj, evidence, line, detail, records, low=False):
        stmt = by_seq.get(anchor_seq) if anchor_seq is not None else None
        if any(not r.parse_ok for r in records):
            add(stmt, obj, evidence, line, detail, "token")
        else:
            add(stmt, obj, evidence, line, detail, "ast",
                confidence="low" if low else "high")

    for seg in interp.segments:
        later = _later(interp.segments, seg) if check == "tx_implicit_commit_cut" else None
        detail = _detail(seg, later)
        if check == "tx_implicit_commit_cut" and seg.status == S_CUT and seg.cut_line:
            before = _summary(seg.committed_before_cut) or "无待提交 DML"
            after = _summary(later)
            evidence = (
                f"{config.dialect} 方言下 L{seg.cut_line} 的 DDL 触发隐式提交，"
                f"BEGIN(L{seg.begin_line}) 后 {len(seg.committed_before_cut)} 条变更"
                f"已在该语句前提交且不可由后续 ROLLBACK 撤回: {before}")
            if after:
                evidence += f"；切断后自动提交区域另有: {after}"
            emit(seg.begin_seq, file.rel_path, evidence, seg.begin_line, detail,
                 seg.committed_before_cut + later + seg.side_effects)
        elif check == "tx_non_rollbackable_side_effect":
            rolled = seg.status in (S_ROLLED_BACK, S_ROLLED_BACK_UNPROVEN)
            for effect in seg.side_effects:
                tail = "ROLLBACK 后该对象副作用仍然存在" if rolled else "该副作用不能由 ROLLBACK 撤销"
                emit(effect.seq, effect.object_name,
                     f"L{effect.start_line} 的语句不切断当前事务，但其副作用不可回滚，{tail}: "
                     f"{effect.kind} {effect.object_name}（{effect.reason}）",
                     effect.start_line, detail, [effect])
        elif check == "tx_forbidden_in_transaction":
            for item in seg.forbidden:
                emit(item.seq, item.object_name,
                     f"{config.dialect} 方言禁止该语句出现在显式事务内（BEGIN@L{seg.begin_line}）: "
                     f"L{item.start_line} {item.kind} {item.object_name}（{item.reason}）",
                     item.start_line, detail, [item])
        elif check == "tx_unclosed_transaction" and seg.close_kind == C_EOF:
            emit(seg.begin_seq, file.rel_path,
                 f"显式事务 BEGIN@L{seg.begin_line} 没有配对的 COMMIT/ROLLBACK，"
                 "失败后的提交归属无法由脚本自身保证", seg.begin_line, detail,
                 [by_seq[seg.begin_seq]], low=not seg.proven)
        elif check == "tx_boundary_unknown" and not seg.proven:
            unknown = by_seq[seg.unknown_from_seq] if seg.unknown_from_seq else None
            line = unknown.start_line if unknown else seg.begin_line
            emit(seg.begin_seq, file.rel_path,
                 f"事务 BEGIN@L{seg.begin_line} 在 L{line} 出现目标方言无法证明事务效果的语句"
                 f"（{seg.unknown_reason}），该点之后的提交归属未证；不得宣称整段可原子回滚",
                 seg.begin_line, detail, [unknown] if unknown else [], low=True)
