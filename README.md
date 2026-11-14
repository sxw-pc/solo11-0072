# 迁签审台（qianshen-audit）

迁签审台是一个**完全离线的 SQL 迁移脚本静态评审工具**。它读取本地版本化迁移目录，解析 SQL 结构，核对 up/down 回滚配对，按声明式 YAML 规则生成发现，输出 JSON / Markdown / 自包含 HTML 报告，并把每次运行写入 SQLite 审计台账。

它面向迁移评审与留痕，不连接数据库、不执行 SQL、不修改迁移文件，也不自动生成修复 SQL。

> 合规声明：仅分析本人拥有或已获授权的本地迁移脚本；不连接数据库、不执行 SQL、不修改源文件。

## 1. 定位与非目标

### 做什么

- 发现 `NNNN_description.up.sql` / `.down.sql` 或单文件迁移。
- 用 `sqlglot` 做静态语法解析与语句分类，解析失败时使用保守令牌降级。
- 检查版本链、命名宽度、重复版本、缺口、混合布局与 baseline 漂移。
- 检查破坏性 DDL、危险 DML、NOT NULL 新增列、类型收窄/不兼容、锁与可用性风险、重入性、权限变更。
- 核对 up/down 是否存在、是否为空、对象覆盖是否匹配、down 是否引入新的破坏性操作，以及不可逆变更是否有人工确认标记。
- 输出工程可解释的幂等性评分与扣分原因。
- 处理有期限的豁免，展示过期豁免，计算与上次运行的差异。
- 生成确定性报告与 SQLite 台账，提供 CI 可用的退出码。

### 不做什么

- 不连接任何数据库，不执行迁移、回滚、DDL、DML、权限变更或事务。
- 不做 schema 演进门禁编排、SQL 血缘分析、慢查询审计、指标校准、采样、脱敏、爬虫或湖仓工具。
- 不修改输入迁移文件，不自动改写、修复、补全或重排 SQL。
- 不替代人工评审，不保证迁移在目标数据库上一定成功或一定可回滚。

## 2. 环境与安装

要求 Python 3.11+。运行期依赖仅 `sqlglot` 与 `PyYAML`；台账使用标准库 `sqlite3`；CLI 使用标准库 `argparse`。

```bash
python -m pip install -e .
```

安装后可使用控制台命令：

```bash
qianshen-audit audit --config qianshen.yml --migrations fixtures/migrations_risky --out out/
```

也可以不安装、直接以模块方式运行（需让 `src/` 在 `PYTHONPATH` 中）：

```bash
PYTHONPATH=src python -m qianshen audit --config qianshen.yml --migrations fixtures/migrations_risky --out out/
```

开发测试：

```bash
pytest -q
```

## 3. 快速开始

### 3.1 运行六个 fixture 的离线演示

```bash
python -m qianshen demo --out .qianshen-demo
```

演示命令本身在全部场景完成后返回 `0`；每个 fixture 的真实审计退出码记录在 `demo_summary.json` 与索引页中。

输出结构：

```text
.qianshen-demo/
├── index.html                 # 自包含索引页，无外部资源
├── demo_summary.json          # 六个场景的摘要、退出码、发现数与幂等分
├── good/
│   ├── audit-config.yml
│   ├── findings.json
│   ├── report.md
│   ├── report.html
│   └── ledger.sqlite3
├── risky/
│   └── ... 同上
├── conflict/
│   └── ... 同上
├── missing_down/
│   └── ... 同上
├── dialects/
│   └── ... 同上
└── exempted/
    └── ... 同上
```

六个 fixture 分别覆盖：正常迁移、危险变更、版本冲突、缺失回滚、三种方言、有效/过期豁免。

### 3.2 评审一个迁移目录

```bash
python -m qianshen audit \
  --config qianshen.yml \
  --migrations fixtures/migrations_risky \
  --out out/
```

常用覆盖参数：

```bash
python -m qianshen audit \
  --config qianshen.yml \
  --migrations fixtures/migrations_good \
  --out out-good \
  --ledger out-good/ledger.sqlite3 \
  --now 2026-01-01T00:00:00Z \
  --fail-on warning
```

`--fail-on` 可取 `none`、`info`、`warning`、`blocker`。默认只有 `blocker` 影响退出码。

支持的文件命名：

```text
NNNN_description.up.sql      # 成对模式 up
NNNN_description.down.sql    # 成对模式 down
NNNN_description.sql         # 单文件模式
```

`NNNN` 默认 4 位零填充；描述只允许字母、数字、下划线与连字符。方言支持 `postgres`、`mysql`、`sqlite`。`sqlglot` 无法解析时降级为 token 扫描，保留定位并降低置信度，不中断整批任务。

## 4. 目录结构

```text
.
├── README.md
├── pyproject.toml
├── qianshen.yml                 # 默认主配置，指向 risky fixture
├── rules/default.yml            # 默认声明式规则集
├── fixtures/
│   ├── exemptions.yml
│   ├── migrations_good/
│   ├── migrations_risky/
│   ├── migrations_conflict/
│   ├── migrations_missing_down/
│   ├── migrations_dialects/
│   └── migrations_exempted/
├── src/qianshen/
│   ├── __main__.py              # python -m qianshen
│   ├── cli.py                   # argparse 入口
│   ├── config.py                # YAML 配置校验
│   ├── discovery.py             # 文件发现、命名、忽略、校验和
│   ├── sql_split.py             # 注释/字符串/美元引号安全的语句切分
│   ├── sql_parse.py             # sqlglot AST 分类与降级
│   ├── sql_fallback.py          # 解析失败时的保守令牌分类
│   ├── type_compare.py          # 跨版本类型收窄/不兼容判断
│   ├── version_chain.py         # 版本链、baseline、输入清单
│   ├── rules_engine.py          # YAML 规则加载、作用域、匹配
│   ├── file_checks.py           # 文件级规则检查
│   ├── rollback_pair.py         # up/down 配对与不可逆核验
│   ├── idempotency.py           # 可解释幂等性评分
│   ├── exemptions.py            # 豁免加载、过期与命中
│   ├── diffing.py               # 稳定指纹差异
│   ├── ledger.py                # SQLite 台账
│   ├── report_json.py           # findings.json
│   ├── report_markdown.py       # report.md
│   ├── report_html.py           # report.html
│   ├── audit.py                 # 流水线与退出码
│   ├── demo.py                  # 六场景演示
│   ├── models.py
│   └── util.py
├── tests/                       # 70 个离线、确定性 pytest 用例
└── docs/
    ├── RULES.md
    ├── OUTPUT_SCHEMA.md
    └── COMPLIANCE.md
```

## 5. 配置说明

最小配置示例：

```yaml
project: qianshen-audit
version: 1
migrations_dir: fixtures/migrations_risky
dialect: postgres
naming:
  mode: auto          # auto | paired | single
  version_width: 4
ignore:
  dirs: [.git, __pycache__, node_modules]
  globs: ["*.tmp.sql", "*.sql.bak"]
  paths: []
rules_file: rules/default.yml
exemptions_file: null
baseline_file: null
output_dir: out
ledger_path: .qianshen/ledger.sqlite3
fail_on: blocker
clock: "2026-01-01T00:00:00Z"
large_tables: [demo_events]
permissions:
  allow_grants: false
pairing:
  check_rollback: true
irreversible_approvals: []
rule_overrides: {}
```

- `dialect`：`postgres`、`mysql` 或 `sqlite`。
- `naming.mode`：`auto` 同时接受成对与单文件；`paired` / `single` 强制对应布局。
- `clock`：注入固定时钟。报告、运行 ID、豁免到期判断均使用它，便于复现。
- `large_tables`：仅用于演示/触发“大表 DDL 在线策略”规则，工具不会探测真实表规模。
- `permissions.allow_grants`：为 `false` 时，GRANT/REVOKE 触发权限规则。
- `pairing.check_rollback`：关闭后只跳过 up/down 配对核验，其余检查不受影响。
- `irreversible_approvals`：按相对路径通配符承认人工确认；文件内注释标记优先。
- `rule_overrides`：按规则 ID 覆盖 `severity` / `enabled` 等字段。
- `baseline`（可选）：用 `severity_modified`、`severity_deleted`、`severity_added` 分别设置基线修改、删除、新增发现的严重级别；新增默认 warning，不直接阻断。

规则字段：`id`、`title`、`severity`、`category`、`applies_to`、`match`、`message`、`suggestion`、`enabled`，并可附加 `dialects`、`directions`、`path_globs` 作用域。豁免字段：`id`、`rule_id`、`path_glob`、`version`、`fingerprint`、`reason`、`expires_on`；其中 `reason` 与 `expires_on` 必填。

所有配置路径均相对于配置文件所在目录解析；报告中的文件路径统一使用 POSIX 相对路径。

## 6. 输出与退出码

每次审计在 `output_dir` 生成：

- `findings.json`：机器可读的完整报告，固定键顺序与固定发现排序。
- `report.md`：面向人工复核的 Markdown 摘要。
- `report.html`：单文件自包含报告，内联 CSS，无脚本、无外部资源。
- SQLite 台账（默认 `.qianshen/ledger.sqlite3`）：追加写入，不覆盖历史运行。

退出码：

| 退出码 | 含义 |
|---|---|
| 0 | 没有达到 `fail_on` 阈值的活跃发现 |
| 1 | 存在达到阈值的活跃发现 |
| 2 | 配置、输入目录、规则或豁免文件错误 |
| 3 | 内部解析、报告或台账写入错误 |

默认阈值是 `blocker`；`--fail-on warning` 会把 warning 也视为阻断；`--fail-on none` 始终返回 0（配置或内部错误仍返回 2/3）。

报告只包含**截断后的证据**、对象名与定位信息，不复制完整 SQL 原文。豁免项不会被静默丢弃：活跃发现、已豁免发现、过期豁免分别列出。

`findings.json` 顶层包含运行元数据、配置摘要、输入清单、统计汇总、`findings`、`exempted_findings`、`expired_exemptions`、解析警告、回滚配对、幂等评分、运行间差异与规则快照。SQLite 台账至少包含 8 张表：`runs`、`files`、`statements`、`findings`、`rule_snapshots`、`exemptions_applied`、`diffs`、`errors`；逐字段说明见 [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md)。

详细字段、SQLite 表结构和确定性说明见 [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md)。

## 7. 规则概览

默认规则集位于 `rules/default.yml`，共 20 条，覆盖：

- 破坏性 DDL：DROP TABLE、DROP COLUMN、TRUNCATE、DROP CONSTRAINT、DROP INDEX。
- 危险 DML：无 WHERE 的 UPDATE / DELETE。
- 约束风险：NOT NULL 新增列且无默认值、无同文件回填。
- 类型风险：跨版本类型收窄与不兼容变更。
- 锁与可用性：大表离线 DDL、DDL/DML 同事务、长事务标记。
- 重入性：缺少 IF NOT EXISTS / IF EXISTS、同文件重复对象、固定主键 INSERT、累计更新。
- 权限：默认不允许 GRANT / REVOKE。

规则采用声明式 YAML，可限定方言、方向（`up` / `down` / `single`）与路径通配符；严重级别可覆盖。完整规则字段、匹配语义与默认规则清单见 [docs/RULES.md](docs/RULES.md)。

解析失败时，工具使用保守令牌分类，**不丢弃可能的危险语句**；来自令牌降级的发现会降低一级严重级别并标记 `confidence: low`，同时写入解析警告。

## 8. 回滚配对与不可逆标记

- 每个版本必须有同名 up/down 文件（单文件模式会明确提示跳过配对）。
- down 文件不能为空或只有注释。
- 工具比较表、列、索引、约束、视图、类型等对象键；down 未覆盖主要对象时报告对象不匹配。
- down 中出现 up 未涉及的对象或额外破坏性操作时给出警告。
- up 中的 DROP TABLE / DROP COLUMN / TRUNCATE 被记录为不可逆变更；未确认时阻断。
- 人工确认可写在 up 文件注释中：

```sql
-- qianshen: irreversible approved-reason="demo fixture manual review"
DROP TABLE IF EXISTS demo_archive;
```

该标记只承认“已评审”，不会跳过规则检查，也不会掩盖破坏性 DDL 发现。

## 9. 豁免与 baseline

豁免条目必须有 `reason` 与 `expires_on`，并至少提供 `rule_id`、`path_glob`、`version`、`fingerprint` 之一。过期豁免不再生效，但会作为 `config.exemption_expired` 警告出现在报告中。

baseline 文件记录文件路径、版本、方向与 SHA-256。后续运行会报告 `baseline.file_modified`、`baseline.file_deleted`、`baseline.file_added`。

运行间差异基于稳定发现指纹（规则、相对文件、版本、方向、对象、截断证据、结构细节），不包含行号，因此插入空行不会把同一发现误判为“新增”。

## 10. 确定性与离线保证

- 固定排序：严重级别降序 → 版本升序 → 文件路径 → 行号 → 规则 ID → 指纹。
- JSON 使用固定键顺序与 `ensure_ascii=False`；HTML/Markdown 不使用随机内容。
- 时钟由配置或 `--now` 注入，默认 `2026-01-01T00:00:00Z`。
- 运行 ID 由工具版本、时钟、配置摘要、规则摘要、输入清单摘要与发现状态共同决定。
- 运行期不发起网络请求，不依赖 CDN、云服务、外部 API、远程数据库或在线规则源。
- 不读取或写入真实凭据、连接串、公司名、域名或生产迁移数据；所有 fixture 均为合成占位。

## 11. 测试

```bash
pytest -q
```

共 70 个用例，覆盖文件发现、SQL 切分/解析/降级、版本链/baseline、规则与覆盖、回滚配对、幂等评分、豁免、差异、SQLite 台账、三种报告、CLI/demo、确定性与项目约束。测试全部离线，使用 `tmp_path`，不需要数据库或网络。

## 12. 已知限制

- 静态分析无法得知真实数据分布、表规模、锁等待、执行计划或业务约束。
- `sqlglot` 对不同方言的覆盖不完整；不支持的语句会降级为令牌分类，发现置信度降低。
- 复杂存储过程、触发器、PL/pgSQL、动态 SQL、`EXECUTE` 拼接与厂商私有语法可能只做降级提示，不能等同完整语义分析。
- 回滚配对采用对象键启发式，不能证明数据可逆；复杂数据迁移、分区、触发器、存储过程等需要人工复核。
- 幂等性分是工程可解释指标，不是事务安全证明，也不保证重复执行一定安全。
- 大表判断依赖配置中的 `large_tables` 占位名单，不做任何运行时探测。
- 工具不生成、不重写、不执行 SQL；修复建议仅为文字说明。
- demo 通过相对路径定位项目 fixtures，请在项目根目录运行。

## 13. 合规说明

本工具只读输入迁移目录，输出仅写入用户指定目录与 SQLite 台账，不修改原始 fixture；不连接数据库、不执行 SQL、不发起网络请求、不包含真实凭据或生产数据。详细边界见 [docs/COMPLIANCE.md](docs/COMPLIANCE.md)。
