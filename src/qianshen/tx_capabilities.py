"""按目标方言声明的事务能力表。

每种方言对每类语句显式声明五种边界效果之一：保持事务、执行前隐式提交、
执行后隐式提交、禁止出现在显式事务、效果未知；同时给出副作用可否回滚。
未建模语句一律 unknown，绝不假装保持原子性。
"""
from __future__ import annotations
from .models import StatementInfo
from .sql_parse import DDL_KINDS
from .tx_models import (
    COMMIT_BEFORE, COMMIT_BOTH, FORBIDDEN, KEEP, UNKNOWN, TxEffect,
)
_DML = ("insert", "update", "delete")
_TXN_DDL = tuple(DDL_KINDS)
_B = {
    "pg_ddl": "PostgreSQL 事务型 DDL：ALTER/CREATE/DROP/TRUNCATE 可在单个事务内随 ROLLBACK 撤销",
    "pg_conc": "PostgreSQL 的 CREATE/DROP INDEX CONCURRENTLY 不能在事务块中执行",
    "pg_temp": "PostgreSQL 临时表参与事务，ROLLBACK 会撤销其创建",
    "pg_grant": "PostgreSQL GRANT/REVOKE 具备事务性，可随 ROLLBACK 撤销",
    "sq_ddl": "SQLite 的 DDL 具备事务性，CREATE/ALTER/DROP 可随 ROLLBACK 撤销",
    "sq_temp": "SQLite 临时表可随事务回滚，ROLLBACK 会撤销其创建",
    "sq_trunc": "SQLite 无 TRUNCATE 语句，该形态的事务效果无法证明",
    "my_ddl": "MySQL DDL 在执行前隐式提交当前事务，且 DDL 自身不可回滚",
    "my_ctas": "MySQL CREATE TABLE ... SELECT 执行前后各触发一次隐式提交",
    "my_temp": "MySQL CREATE TEMPORARY TABLE 不隐式提交、不切断事务，但临时表在 ROLLBACK 后仍存在",
    "my_drop_temp": "MySQL DROP TEMPORARY TABLE 不隐式提交，但该删除不能由 ROLLBACK 撤回",
    "my_dml": "MySQL 普通 DML 在显式事务内保持未提交，可随 ROLLBACK 撤销",
    "my_grant": "MySQL GRANT/REVOKE 触发隐式提交，且不可回滚",
    "unknown_stmt": "该语句类别在目标方言下的事务效果未建模，边界标记为未知",
    "unknown_dialect": "目标方言不在受支持事务能力表内，不能证明任何事务边界",
    "nest_my": "MySQL 中 BEGIN/START TRANSACTION 会先隐式提交已打开的事务再开新事务",
    "nest_pg": "PostgreSQL 事务内再次 BEGIN 仅产生 WARNING，不会提交或新建事务",
    "nest_sq": "SQLite 不允许事务内再次 BEGIN，运行期会报错",
}
# 各方言对“事务内再次 BEGIN”的处理：(边界效果, 依据)
NESTED_BEGIN = {
    "postgres": (KEEP, _B["nest_pg"]),
    "sqlite": (FORBIDDEN, _B["nest_sq"]),
    "mysql": (COMMIT_BEFORE, _B["nest_my"]),
}

def _conf(stmt: StatementInfo) -> str:
    return "high" if stmt.parse_ok else "low"

def _unknown(stmt: StatementInfo, basis: str) -> TxEffect:
    return TxEffect(UNKNOWN, None, True, "low", basis)

def _postgres(stmt: StatementInfo) -> TxEffect:
    if stmt.kind in _DML: return TxEffect(KEEP, True, True, _conf(stmt), "PostgreSQL 显式事务内 DML 可随 ROLLBACK 撤销")
    if stmt.kind not in _TXN_DDL: return _unknown(stmt, _B["unknown_stmt"])
    if stmt.attrs.get("concurrently"): return TxEffect(FORBIDDEN, False, False, _conf(stmt), _B["pg_conc"])
    if stmt.kind == "create_table" and stmt.attrs.get("temporary"):
        return TxEffect(KEEP, True, True, _conf(stmt), _B["pg_temp"])
    if stmt.kind in ("grant", "revoke"): return TxEffect(KEEP, True, True, _conf(stmt), _B["pg_grant"])
    return TxEffect(KEEP, True, True, _conf(stmt), _B["pg_ddl"])

def _sqlite(stmt: StatementInfo) -> TxEffect:
    if stmt.kind in _DML: return TxEffect(KEEP, True, True, _conf(stmt), "SQLite 显式事务内 DML 可随 ROLLBACK 撤销")
    if stmt.kind == "truncate": return _unknown(stmt, _B["sq_trunc"])
    if stmt.kind in ("grant", "revoke", "create_type", "alter_type"): return _unknown(stmt, _B["unknown_stmt"])
    if stmt.kind not in _TXN_DDL: return _unknown(stmt, _B["unknown_stmt"])
    if stmt.kind == "create_table" and stmt.attrs.get("temporary"):
        return TxEffect(KEEP, True, True, _conf(stmt), _B["sq_temp"])
    return TxEffect(KEEP, True, True, _conf(stmt), _B["sq_ddl"])

def _mysql(stmt: StatementInfo) -> TxEffect:
    if stmt.kind in _DML: return TxEffect(KEEP, True, True, _conf(stmt), _B["my_dml"])
    if stmt.kind in ("grant", "revoke"): return TxEffect(COMMIT_BEFORE, False, True, _conf(stmt), _B["my_grant"])
    if stmt.kind not in _TXN_DDL: return _unknown(stmt, _B["unknown_stmt"])
    if stmt.kind == "create_table":
        if stmt.attrs.get("temporary"): return TxEffect(KEEP, False, True, _conf(stmt), _B["my_temp"])
        if stmt.attrs.get("select_into"): return TxEffect(COMMIT_BOTH, False, True, _conf(stmt), _B["my_ctas"])
        return TxEffect(COMMIT_BEFORE, False, True, _conf(stmt), _B["my_ddl"])
    if stmt.kind == "drop_table" and stmt.attrs.get("temporary"):
        return TxEffect(KEEP, False, True, _conf(stmt), _B["my_drop_temp"])
    if stmt.kind == "truncate":
        return TxEffect(COMMIT_BEFORE, False, True, _conf(stmt), "MySQL TRUNCATE 属于 DDL，隐式提交且不可回滚")
    return TxEffect(COMMIT_BEFORE, False, True, _conf(stmt), _B["my_ddl"])

_RESOLVERS = {"postgres": _postgres, "sqlite": _sqlite, "mysql": _mysql}

def statement_effect(dialect: str, stmt: StatementInfo) -> TxEffect:
    """查询能力表，返回语句在目标方言下的事务效果。"""
    resolver = _RESOLVERS.get(dialect)
    if resolver is None: return _unknown(stmt, _B["unknown_dialect"])
    return resolver(stmt)

def dialect_supported(dialect: str) -> bool:
    return dialect in _RESOLVERS
