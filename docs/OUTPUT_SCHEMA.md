# 输出与台账结构

一次成功审计会在 `output_dir` 生成 `findings.json`、`report.md`、`report.html`，并向 `ledger_path` 追加一组 SQLite 记录。所有对外路径均为 POSIX 相对路径；不写绝对用户目录。

## 1. 通用约定

- JSON：UTF-8、`ensure_ascii=False`、两空格缩进、末尾换行，键顺序固定。
- 严重级别：`blocker` > `warning` > `info`。
- 发现状态：`active` 或 `exempted`。
- 证据与建议：证据截断至 180 字符，建议截断至 240 字符；报告不复制完整 SQL 原文。
- 排序：严重级别降序 → 版本升序 → 文件路径 → 起始行 → 规则 ID → 指纹。
- 指纹：`qf-` 前缀 + 16 位 SHA-256 截断，不包含行号。
- 时钟：来自配置 `clock` 或 `--now`，默认 `2026-01-01T00:00:00Z`。

## 2. findings.json

顶层字段：

| 字段 | 类型 | 含义 |
|---|---|---|
| `schema_version` | string | 当前为 `1.0` |
| `tool` | object | `name`、`title`、`version` |
| `run` | object | `run_id`、起止时间、方言、阈值、结论、退出码、复现命令 |
| `configuration` | object | 不含绝对路径的配置摘要 |
| `input` | object | 文件总数、方向统计、版本、布局、清单 SHA-256、版本链结果 |
| `summary` | object | 文件/语句/发现/豁免数量、严重级别、规则与配置摘要 |
| `findings` | array | 活跃发现，按固定顺序排序 |
| `exempted_findings` | array | 已命中豁免的发现，单独保留 |
| `expired_exemptions` | array | 已过期豁免的说明 |
| `parse_warnings` | array | 解析降级警告 |
| `discovery_errors` | array | 发现阶段读取/编码错误 |
| `rollback` | object | 回滚配对结果 |
| `idempotency` | object | 幂等性评分与扣分明细 |
| `diff` | object | 与上次运行的差异 |
| `rule_snapshots` | array | 本次生效的规则快照 |
| `notices` | array | 不构成发现的提示 |

单个发现字段：

| 字段 | 含义 |
|---|---|
| `fingerprint` | 稳定指纹 |
| `rule_id` | 规则 ID |
| `title` | 规则标题 |
| `severity` | `blocker` / `warning` / `info` |
| `category` | 规则类别 |
| `file` | 相对文件路径 |
| `version` | 版本号或 null |
| `direction` | `up` / `down` / `single` / `mixed` |
| `statement_seq` | 文件内语句序号或 null |
| `line_start` / `line_end` | 行号范围 |
| `object_name` | 表、列、索引、约束、视图、类型等对象 |
| `evidence` | 截断证据 |
| `suggestion` | 截断建议 |
| `source` | `ast` / `token` / `file` / `config` |
| `confidence` | `high` / `low` |
| `status` | `active` / `exempted` |
| `exemption_id` | 命中豁免 ID 或 null |

`findings` 只含活跃发现；`exempted_findings` 形如：

```json
{
  "exemption_id": "ex-valid-drop",
  "reason": "demo fixture: manual review",
  "expires_on": "2030-01-01",
  "finding": { "...": "完整发现字段" }
}
```

## 3. rollback

```json
{
  "enabled": true,
  "counts": {"pairs": 6, "ok": 3, "issues": 3},
  "pairs": [
    {
      "version": 1,
      "up": "0001_create.up.sql",
      "down": "0001_create.down.sql",
      "status": "ok",
      "evidence_source": "ast",
      "up_objects": ["table:demo_x"],
      "down_objects": ["table:demo_x"],
      "missing_objects": [],
      "extra_objects": [],
      "irreversible_changes": [],
      "findings": []
    }
  ],
  "notices": []
}
```

`status` 取值：`ok`、`missing_down`、`empty_down`、`object_mismatch`、`irreversible`、`warnings`、`foreign_key_order`、`foreign_key_unconfirmed`。`evidence_source` 为 `ast`、`token` 或 `none`。每个不可逆变更条目带有 `marker: "irreversible_change"`，并记录 `approved` 与 `approved_reason`；标记只影响分类与提示，不跳过其他检查。

每个配对还包含 `foreign_key_order` 外键顺序审查块：

```json
{
  "version": 1,
  "status": "foreign_key_order",
  "edges": [
    {
      "constraint": "fk_child_parent",
      "source_table": "child",
      "referenced_table": "parent",
      "defined_file": "0001_x.up.sql",
      "defined_seq": 2,
      "live": true
    }
  ],
  "unconfirmed": [],
  "order_findings": ["qf-…"],
  "unconfirmed_findings": []
}
```

- `edges` 记录本版本 up 识别到的外键边（CREATE TABLE 内联 REFERENCES、表级 FOREIGN KEY 或 ALTER TABLE ADD CONSTRAINT），无显式约束名时使用 `__anon_fk_` 前缀的合成名；`live` 表示到当前版本为止该约束是否仍然存在。
- 审查规则：up 中被引用表（父表）必须先于依赖表（子表）创建；down 中依赖表必须先于被引用表删除。违反时产生 `rollback.foreign_key_order` 阻断发现，证据携带依赖边与父/子表两条语句的文件与行号。
- 自引用外键与无关表不产生阻断；后续版本已经 DROP CONSTRAINT 的外键不会永久阻断更早版本的父表删除（down 按版本降序模拟真实回滚顺序）。
- 同一语句删除多个表、同语句多动作、表改名或解析降级导致顺序无法确认时，不宣称通过，而是产生 `rollback.foreign_key_unconfirmed`（token 来源下降级为 info / low confidence），条目记录在 `unconfirmed` 中。

`input.version_chain.expected` 按版本号列出已发现的 `directions`，与 `manifest` 一起构成确定性的期望清单和文件指纹清单。

## 4. idempotency

```json
{
  "score": 84,
  "method": "100 分起扣，按文件取平均；扣分项见下，不代表事务安全证明",
  "files": [
    {"file": "0001_x.up.sql", "version": 1, "direction": "up", "score": 70,
     "reasons": [{"code": "unconditional_dml", "delta": -15, "message": "..."}]}
  ],
  "reason_counts": {"unconditional_dml": 1},
  "low_score_files": [{"file": "0001_x.up.sql", "score": 70}]
}
```

评分只用于工程可解释性，不是事务安全证明。空输入按 100 分处理；无扣分文件不参与平均。

## 5. diff

`diff` 基于指纹比较：

- `new`：本次活跃、上次不存在。
- `fixed`：上次活跃、本次不存在。
- `persistent`：两次均活跃。
- `exempted`：本次命中豁免。
- `baseline_available`：是否存在可比较的上一次运行。
- `previous_run_id`：对比的运行 ID。
- `items`：按类别顺序、严重级别降序、文件、指纹排序。
- `counts`：四类计数。

首次运行没有历史时，全部活跃发现记为 `new`。

## 6. report.md 与 report.html

Markdown 固定章节：阻断项、统计汇总、重点发现、回滚配对、幂等性摘要、豁免说明、运行间差异、解析警告与输入错误、提示、复现命令。

HTML 为单文件自包含报告：

- 内联 `<style>`；
- 无 `<script>`、`<link>`、`<img>`、`src=`、`@import`、`url(`；
- 无 `http://` / `https://` 等外部地址；
- 所有动态文本经 HTML 转义；
- 仅展示前 40 条重点发现，完整列表指向 `findings.json`。

## 7. SQLite 台账

台账使用标准库 `sqlite3`，每次运行在单个事务中插入全部记录。表结构稳定，追加写入，不覆盖历史。

### runs

`id`（自增主键）、`run_id`、`started_at`、`ended_at`、`tool_version`、`project`、`dialect`、`fail_on`、`config_sha256`、`rules_sha256`、`input_sha256`、`input_dir`、`conclusion`、`exit_code`、`files_count`、`findings_count`、`blocking_count`、`summary_json`。

### files

`run_pk`、`rel_path`、`version`、`direction`、`description`、`size_bytes`、`line_count`、`sha256`、`naming_error`、`mtime_placeholder`。主键 `(run_pk, rel_path)`。

### statements

`run_pk`、`file_rel`、`seq`、`start_line`、`end_line`、`kind`、`ast_kind`、`is_ddl`、`is_dml`、`is_transaction`、`objects_json`、`actions_json`、`summary`、`sha256`、`parse_ok`、`parse_warning`、`source`、`attrs_json`。主键 `(run_pk, file_rel, seq)`。

### findings

`run_pk`、`fingerprint`、`rule_id`、`title`、`severity`、`category`、`file_rel`、`version`、`direction`、`statement_seq`、`line_start`、`line_end`、`object_name`、`evidence`、`suggestion`、`source`、`confidence`、`status`、`exemption_id`。主键 `(run_pk, fingerprint, rule_id)`。

### rule_snapshots

`run_pk`、`rule_id`、`severity`、`category`、`enabled`、`rule_json`。主键 `(run_pk, rule_id)`。

### exemptions_applied

`run_pk`、`exemption_id`、`finding_fingerprint`、`rule_id`、`path_glob`、`version`、`reason`、`expires_on`。主键 `(run_pk, exemption_id, finding_fingerprint)`。

### diffs

`run_pk`、`category`、`fingerprint`、`rule_id`、`severity`、`file_rel`、`summary`。主键 `(run_pk, category, fingerprint)`。

### errors

`run_pk`、`stage`、`file_rel`、`line`、`code`、`message`。记录发现阶段读取/编码错误与解析降级警告，消息截断至 300 字符。

## 8. 退出码

| 退出码 | 条件 |
|---|---|
| 0 | 没有活跃发现达到 `fail_on` 阈值，或阈值为 `none` |
| 1 | 至少一条活跃发现达到阈值 |
| 2 | 配置、输入、规则、豁免或 baseline 错误 |
| 3 | 解析流程、报告或台账写入的内部错误 |

豁免的发现不参与退出码判定；过期豁免以 warning 发现形式存在，是否阻断取决于阈值。解析降级后的发现使用降级后的严重级别参与判定。

## 9. 复现性

- `run_id` 由工具版本、固定时钟、配置摘要、规则集摘要、输入清单摘要与发现状态共同生成。
- 相同配置、相同输入、相同规则在相同工具版本下产生相同的 `run_id`、排序与报告字节内容。
- 输入清单 SHA-256 基于相对路径、版本、方向与文件字节 SHA-256，与机器时间、绝对路径无关。
- 第二次运行会在台账追加新记录；若输入与发现完全一致，运行 ID 相同，差异比较会排除当前运行 ID，避免把自身当作历史基线。
