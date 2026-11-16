# 规则说明

规则集是声明式 YAML，默认位于 `rules/default.yml`，按规则 ID 排序加载。每条规则只描述“在什么结构上产生什么发现”，不会执行 SQL，也不会生成修复语句。

## 1. 规则结构

```yaml
rules:
  - id: destructive.drop_materialized_view
    title: 删除物化视图
    severity: blocker          # blocker | warning | info
    category: destructive_ddl
    applies_to: [statement]    # statement | file
    match:
      kind: [drop_view]
    directions: [up, single]   # 可选：up | down | single
    dialects: [postgres]       # 可选：postgres | mysql | sqlite
    path_globs: ["*.up.sql"]   # 可选：相对路径通配符
    message: "对象 {object} 被删除"
    suggestion: "确认已归档并补充可恢复方案。"
    enabled: true
```

必填字段：`id`、`severity`、`match`。`id` 必须唯一；`severity` 只能是 `blocker`、`warning`、`info`。

`message` 与 `suggestion` 支持占位符：`{file}`、`{object}`、`{line}`、`{version}`、`{direction}`、`{evidence}`。未知占位符不会导致运行失败，原模板会保留。

## 2. match 条件

| 字段 | 含义 |
|---|---|
| `kind` | 语句类别，字符串或列表，精确匹配 |
| `actions_any` | ALTER 动作集合与给定列表有交集 |
| `where` | DML 是否包含 WHERE |
| `if_not_exists` / `if_exists` | DDL 是否声明幂等保护 |
| `not_null` / `has_default` | 新增列属性 |
| `type_change` | `narrowing` / `widening` / `incompatible` / `unknown` |
| `permission_not_allowed` | 为 true 且配置不允许授权时匹配 GRANT/REVOKE |
| `requires_no_backfill` | 为 true 时，同文件没有指向同表的 UPDATE 才匹配 |
| `large_table` | 表名位于配置 `large_tables` 时匹配 |
| `sql_regex` | 对语句原文做大小写不敏感正则匹配（仅用于静态证据） |
| `check` | 使用内置文件级检查器，见下表 |

未知条件、未知检查器、无效正则都会以退出码 2 拒绝运行，不做静默忽略。

文件级检查器：

- `large_table_ddl_offline`：大表 DDL 未体现在线/分批策略。
- `ddl_dml_in_transaction`：同一事务中出现 DDL 与 DML（结构性提示，不判断方言提交语义）。
- `tx_implicit_commit_cut`：目标方言的 DDL 在显式事务中途隐式提交，切断原子性。
- `tx_non_rollbackable_side_effect`：语句不切断事务但副作用不可回滚（如 MySQL 临时表）。
- `tx_forbidden_in_transaction`：语句在目标方言中禁止出现在显式事务内。
- `tx_unclosed_transaction`：显式 BEGIN 缺少配对的 COMMIT/ROLLBACK。
- `tx_boundary_unknown`：事务内含目标方言无法证明事务效果的语句，原子性未证。
- `long_transaction_marker`：文件声明/呈现长事务风险标记。
- `duplicate_object`：同一文件重复定义表、视图、类型、索引或新增列。
- `fixed_key_insert`：INSERT 使用固定主键字面量。
- `non_idempotent_dml`：累计更新等重复执行不安全的 DML 形态。

## 3. 默认规则清单

| 规则 ID | 严重级别 | 类别 | 触发条件 |
|---|---|---|---|
| `destructive.drop_table` | blocker | destructive_ddl | up/single 中 DROP TABLE |
| `destructive.drop_column` | blocker | destructive_ddl | up/single 中 DROP COLUMN |
| `destructive.truncate` | blocker | destructive_ddl | up/single 中 TRUNCATE |
| `destructive.drop_constraint` | warning | destructive_ddl | up/single 中 DROP CONSTRAINT |
| `destructive.drop_index` | warning | destructive_ddl | up/single 中 DROP INDEX |
| `dml.update_without_where` | blocker | dangerous_dml | UPDATE 无 WHERE |
| `dml.delete_without_where` | blocker | dangerous_dml | DELETE 无 WHERE |
| `schema.add_not_null_without_default` | blocker | constraint_risk | 新增 NOT NULL 列、无默认值、同文件无回填 |
| `schema.type_narrowing` | blocker | type_risk | 跨版本类型收窄 |
| `schema.type_incompatible` | warning | type_risk | 跨版本类型不兼容 |
| `availability.large_table_ddl_without_online` | warning | lock_availability | 配置的大表出现 DDL |
| `availability.ddl_dml_in_transaction` | warning | lock_availability | 同事务 DDL + DML |
| `transaction.implicit_commit_cut` | blocker | transaction_integrity | 方言 DDL 隐式提交切断显式事务 |
| `transaction.non_rollbackable_side_effect` | blocker | transaction_integrity | 不切断事务但不可回滚的副作用（MySQL 临时表等） |
| `transaction.forbidden_in_transaction` | blocker | transaction_integrity | 语句禁止出现在显式事务内 |
| `transaction.unclosed_transaction` | warning | transaction_integrity | BEGIN 缺少配对 COMMIT/ROLLBACK |
| `transaction.boundary_unknown` | warning | transaction_integrity | 含未建模语句，事务原子性未证 |
| `availability.long_transaction_marker` | warning | lock_availability | 长事务标记/形态 |
| `idempotency.create_table_without_if_not_exists` | warning | reentrancy | CREATE TABLE 无 IF NOT EXISTS |
| `idempotency.add_column_without_if_not_exists` | warning | reentrancy | ADD COLUMN 无 IF NOT EXISTS |
| `idempotency.drop_without_if_exists` | warning | reentrancy | DROP TABLE/INDEX/VIEW 无 IF EXISTS |
| `idempotency.duplicate_object_in_file` | warning | reentrancy | 同文件重复定义对象 |
| `idempotency.fixed_key_insert` | warning | reentrancy | 固定主键 INSERT |
| `idempotency.accumulating_update` | warning | reentrancy | 累计更新 |
| `permissions.grant_revoke_not_allowed` | warning | permissions | GRANT/REVOKE 且配置不允许 |

破坏性 DDL、类型、约束与可用性规则默认只作用于 `up` / `single`。down 文件的回滚语义由独立的回滚配对检查核验，避免同一条回滚语句被重复误报。

## 4. 覆盖与作用域

规则覆盖写在主配置：

```yaml
rule_overrides:
  destructive.drop_index:
    severity: info
  idempotency.fixed_key_insert:
    enabled: false
```

- 未知规则 ID 会报配置错误，防止拼写错误被静默接受。
- 覆盖后的规则快照会写入报告与 `rule_snapshots` 表，并参与规则集 SHA-256。
- 作用域按“方言 + 方向 + 路径通配符”依次过滤；三者同时存在时必须全部满足。
- `applies_to` 中的 `file` 用于文件级检查；语句规则仍会针对文件内每条匹配语句生成发现。

## 5. 解析降级

当 `sqlglot` 无法解析某条语句时：

1. 保留语句边界、行号与截断摘要；
2. 使用保守令牌分类识别 DROP、TRUNCATE、UPDATE、DELETE、GRANT 等形态；
3. 该语句仍参与规则匹配，但发现严重级别降低一级（blocker → warning，warning → info，info → info）；
4. 发现标记 `source: token`、`confidence: low`；
5. 解析警告写入报告与台账 `errors` 表。

降级的目的不是“宽容通过”，而是让无法确认的风险继续可见，同时明确证据强度。

## 5.1 方言事务能力与真实提交边界

不能机械地看见 `BEGIN` 就认为整批变更原子。`tx_capabilities` 按目标方言（postgres/mysql/sqlite）对每类语句显式声明五种边界效果之一：保持当前事务（keep）、执行前隐式提交（commit_before）、执行后隐式提交（commit_after）、禁止出现在显式事务（forbidden）、效果未知（unknown），并分别标注语句副作用是否可回滚。解释器把 `StatementInfo` 序列折叠成有序“有效事务段”，逐段标出显式 BEGIN/COMMIT/ROLLBACK、隐式提交切断点、切断前后已提交/待提交对象、不可回滚副作用与未闭合段。

- PostgreSQL：事务型 `ALTER/CREATE/DROP/TRUNCATE` 可在单事务内随 `ROLLBACK` 撤销；但 `CREATE/DROP INDEX CONCURRENTLY` 禁止出现在事务块；临时表参与事务、可回滚。
- MySQL：普通 DDL 在执行前隐式提交当前事务且自身不可回滚；`CREATE TABLE ... SELECT` 执行前后各提交一次；`CREATE/DROP TEMPORARY TABLE` 不隐式提交、不切断事务，但临时对象在 `ROLLBACK` 后仍存在，因此单独出具不可回滚副作用发现。
- SQLite：DDL 具备事务性可回滚；其不支持的形态（如 TRUNCATE）标记为 unknown，不虚构原子性。

对未建模语句或解析降级，解释器保留此前可证明的提交片段，仅把当前打开从事务首个 unknown 效果标记为“边界未证”；不会因为读到 `COMMIT/ROLLBACK` 就把未知前段重写成已证明原子。因此同一份 `BEGIN→UPDATE→ALTER→UPDATE→ROLLBACK` 在 PostgreSQL 下结论为整体可回滚，在 MySQL 下必须指出 `ALTER` 前的 UPDATE 已提交、末尾 ROLLBACK 无法统一撤回；两者不会被压成同一条“混有 DDL”的发现。

## 6. 误报边界

- 规则基于静态结构与关键词，不理解业务语义。例如“删除未使用的临时表”仍会命中破坏性 DDL，需要人工确认或限时豁免。
- 注释中的关键字通常不会进入 AST 分类，但 `sql_regex` 规则可能匹配注释文本，编写自定义规则时应自行约束。
- 动态 SQL、存储过程、触发器、PL/pgSQL、厂商私有语法与 `EXECUTE` 拼接通常只能降级提示，不能证明其行为。
- 大表风险依赖配置 `large_tables` 占位名单，不是真实的表规模或锁等待测量。
- 类型收窄基于声明的类型描述，不分析实际数据是否可转换；`VARCHAR`/精度等跨方言规则可能保守。
- NOT NULL 风险只检查同一文件中指向同表的 `UPDATE` 回填，不分析外部脚本或运行时默认值。
- 幂等性分与重复执行提示是启发式，不构成并发、事务隔离或业务扣减正确性的证明。
- 回滚对象匹配是启发式；视图依赖、数据迁移、分区与触发器需要人工补充核验。

工具对不确定结果采取“保留可见、降低置信度”的策略，而不是静默放行。

## 7. 指纹与排序

发现指纹由规则 ID、相对文件、版本、方向、对象名、截断证据与结构细节组成，不包含行号。排序固定为：

```text
严重级别降序 → 版本升序 → 文件路径 → 起始行 → 规则 ID → 指纹
```

因此插入空行、调整注释不会把同一发现误判为运行间“新增”，有利于台账差异与 CI 稳定复现。
