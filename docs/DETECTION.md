# 本地安全事件检测与告警处置

本模块在原有 FastAPI 服务（`GET /` → `{"Hello": "World"}`，启动方式不变）之上，
新增一套**纯本地存储 + 本地规则文件**的安全事件检测能力。无外部消息队列、无外部
数据库：事件在内存中处理，判定流水（journal）以 fsync 的 JSON-lines 文件落盘，
快照写入本地 JSON 文件。

- 代码包：`detection/`
- 数据目录：默认 `./data`，可用环境变量 `DETECTION_DATA_DIR` 覆盖
- 路由前缀：`/detection`

---

## 1. 事件模型

所有来源（json / cef / leef / syslog）都归一为同一模型 `NormalizedEvent`：

| 字段 | 含义 |
|---|---|
| `event_id` | 幂等键。json 显式提供；CEF 取 `externalId`；LEEF 取 `ident/externalId`；syslog 由整行哈希派生 |
| `source` | `json` / `cef` / `leef` / `syslog` |
| `event_type` | 统一事件类型（json 的 `type`；CEF 的 `signature:name`；LEEF 的 `cat`；syslog 的 app） |
| `severity` | 归一为 `low/medium/high/critical`，序值 10/20/30/40 |
| `occurred_at` | 事件发生时间（unix 秒，UTC） |
| `ingested_at` | 摄入墙钟时间；去重窗口以此为准 |
| `src_ip` / `target` | 可空 |
| `fields` | 来源特有扩展键值（如 `fields.reason`、`fields.count`） |
| `raw_size` / `raw_digest` | 原始字节数与 SHA-256 摘要 |
| `input_digest()` | 归一化后输入的 SHA-256，重放时用于追溯 |

### 规范 JSON 事件

```json
{"event_id": "e1", "type": "login_fail", "severity": "critical",
 "ts": "2026-09-22T10:00:00Z", "src_ip": "10.0.0.1",
 "fields": {"reason": "bad_password"}}
```

- `type` / `severity` / `ts` 必填；`event_id` 缺失即拒绝。
- `severity` 接受 `low..critical`，也接受 CEF 风格 0–10 整数
  （0–3 low，4–6 medium，7–8 high，9–10 critical）。
- `ts` 接受 unix 秒（int/float）或 ISO-8601（允许尾缀 `Z`）。
  - 无法解析 / 超过当前时间 60 秒 → `bad_timestamp`
  - 早于“迟到地平线”（默认 24h）→ `stale_event`
- CEF 示例：`CEF:0|Acme|FW|2.1|400|Block|9|src=9.9.9.9 externalId=c1 rt=2026-09-22T10:00:00Z`
- LEEF 示例：`LEEF:2.0|IBM|Proventia|1.0|evt\tsrc=8.8.8.8\tsev=5\tident=l1\t...`
- syslog 示例：`<13>Sep 22 10:00:00 web01 nginx: GET /admin 500`
  - 严重度由 PRI 的低 3 位映射；无 PRI 时为 `low`。

### 拒绝原因（不会静默丢弃）

| reason | 触发条件 |
|---|---|
| `malformed_json` | HTTP body 不是合法 JSON |
| `malformed_payload` | 单条事件结构不符（非对象、CEF/LEEF 头损坏等） |
| `missing_field` | 必填字段缺失/为空，或 severity 非法 |
| `bad_timestamp` | 时间格式非法、未来时间超偏 |
| `stale_event` | 事件时间早于迟到地平线 |
| `event_too_large` | 单条超过 `max_event_bytes` |
| `batch_too_large` | 批条数或批总字节超限 |
| `batch_empty` | 空批次 / 空 body |
| `unknown_source` | URL 中来源不支持 |
| `over_capacity` | 内存/开放告警达上限（HTTP 503） |

批次级错误（空批、超限）整批拒绝且 **HTTP 非 2xx**；单条错误在响应
`rejected[]` 中带 `index/reason/message/raw_digest` 逐项返回，合法条目照常摄入。

### 幂等

`event_id` 是幂等键。重试、重复投递、同批重复 id 都只生效一次：
- 重复条目不计数，id 出现在响应 `duplicates`；
- 同一 id 的并发投递由存储层锁 + 提交前检查保证恰好一次入库、恰好一次检测。

---

## 2. 规则格式与兼容范围

规则文件：`$DETECTION_DATA_DIR/rules.json`，为 JSON 数组
（或 `{"version": "v2", "rules": [...]}` 包装形式）。

```json
{
  "id": "brute_force_v2",
  "version": "v2",
  "revision": 1,
  "name": "Repeated login failures",
  "condition": {"field": "event_type", "op": "eq", "value": "login_fail"},
  "severity": "critical",
  "dedupe_window_seconds": 300,
  "suppress_key": "login_fail",
  "suppress_severity_ceiling": "medium"
}
```

- `id/version/name/condition/severity` 必填；`revision` 为正整数，缺省 1。
- `condition.field` 可取 `event_type`、`severity`、`src_ip`、`target`、
  `event_id`，或 `fields.<key>`。
- 操作符：
  - **v1 永远只支持** `eq` / `neq` / `contains`；
  - v2 额外支持 `gt/gte/lt/lte`（数值）与 `regex`（合法正则）。
- v2 专属字段：`dedupe_window_seconds`、`suppress_key`、
  `suppress_severity_ceiling`。**v1 文档若携带这些字段会被拒绝**
  （`rule_semantic_unsupported`），保证旧规则语义不被悄悄改变。
- 未知顶层字段/未知条件字段 → `rule_field_unsupported`；
  未知版本 → `rule_version_unsupported`；
  未知操作符、类型不符、非法正则、ceiling 缺少 key → `rule_semantic_unsupported`；
  同文件内 `(id,revision)` 重复 → `rule_duplicate_id`。
- **热更原子性**：`POST /detection/rules/reload` 先完整解析整个文件，任一规则
  失败则活动规则集保持不变（见 `tests/test_rules_compat.py`）。
- **历史保留**：每次修订都保留在规则库中，告警与判定流水绑定命中时的
  `revision + signature`（规则语义内容的 SHA-256）。规则更新不改写旧告警结论。

---

## 3. 检测、去重与抑制

单条事件对当前规则集快照逐一评估，每条规则产生一条判定（命中或未命中），
流水的 `reason` 记录判定依据（实际字段值、操作符、期望值或告警动作）。

- **指纹**：`sha256(rule_id, revision, condition.field, 实际字段值)`。
- **去重窗口**：命中且存在同指纹 OPEN 告警，且 `ingested_at <= 首次 opened_at +
  dedupe_window_seconds`（默认 300s，可配 `default_dedupe_window_seconds`）时折入：
  计数 +1，不产生新告警。窗口按**摄入墙钟时间**判定，边界确定：
  恰好边界内折入，越过 1ms 即新建。迟到事件在窗口内仍确定性折入。
- **抑制**（v2）：命中规则带 `suppress_key`，且已有携带相同 key 的 OPEN 告警、
  指纹不同，并且事件严重度 **≤ 抑制天花板** 时，生成 `suppressed` 子告警，
  `parent_alert_id` 指向抑制源。天花板取触发规则与抑制源规则两者中**更严格**者；
  更高严重度事件**绝不被低优先级抑制吞掉**，而是正常 OPEN。
- **合并**：`POST /detection/alerts/merge` 将子告警置 `merged` 并挂
  `parent_alert_id`，事件计数并入父告警。

---

## 4. 告警状态机

```
OPEN         -> MERGED | SUPPRESSED | ACKNOWLEDGED | RESOLVED
ACKNOWLEDGED -> RESOLVED
SUPPRESSED   -> OPEN          # 更高严重度事件可重新拉起
MERGED       -> (终态)
RESOLVED     -> (终态)
```

- 其余跳转一律 `409 illegal_transition`；对终态重复执行终态操作同样拒绝。
- 告警 id 不存在 → `404 alert_not_found`；目标状态名非法 → `illegal_transition`。
- 乱序/迟到事件不会造成错误跳转：状态迁移只经显式 API 触发，检测路径只创建
  OPEN/SUPPRESSED 或折入，不会直接改既有告警状态。
- 被合并/抑制的告警与父告警通过 `parent_alert_id` 明确区分归属。

---

## 5. 并发、背压与失败卫生

- 服务内一把可重入锁串行化摄入、规则热更、状态迁移、快照/重放准备；
  查询同锁取一致视图。事件评估使用规则集**快照**，不会读到半更新批次。
- 资源上限（`EngineConfig`，见下）：事件存储、开放告警数、批条数、批/条字节数。
  超限按策略**拒绝**（`over_capacity` → HTTP 503；批量超限 → 422），
  容量检查在任何写入之前，失败不产生部分状态。
- journal 每条 append 均 `flush + fsync`；服务关闭（lifespan）释放文件句柄，
  无泄漏。

### 配置项（环境/代码）

| 配置 | 默认 | 说明 |
|---|---|---|
| `DETECTION_DATA_DIR` | `data` | 规则/快照/流水目录 |
| `max_event_bytes` | 65536 | 单条字节上限 |
| `max_batch_events` | 1000 | 每批条数上限 |
| `max_batch_bytes` | 4 MiB | 每批总字节上限 |
| `max_events_in_memory` | 100000 | 事件内存上限（背压） |
| `max_open_alerts` | 10000 | OPEN 告警上限 |
| `late_event_horizon_seconds` | 86400 | 迟到地平线 |
| `default_dedupe_window_seconds` | 300 | 规则未声明窗口时的缺省去重窗口 |

---

## 6. 快照、流水与重放

- 判定流水：`data/journal.log`（JSON-lines，fsync）。每行含
  `seq,event_id,input_digest,rule_id,rule_revision,rule_signature,
  matched,reason,alert_id,at`——每条判定都可追溯到输入摘要与命中规则版本。
- 快照：`POST /detection/detection/snapshot` 原子写出 `data/snapshot.json`
  （临时文件 + `os.replace`）。
- 重放：`POST /detection/replay`
  - 使用隔离的内存存储，绝不触碰线上告警状态；
  - 事件按原始 `ingested_at` 排序，使去重窗口边界落在原处；
  - 按流水记录的 `(rule_id, revision)` 从规则库历史中钉住当时修订评估；
  - 逐条比对原始判定（修订、signature、命中与否、是否产生告警），
    返回 `consistent`、`mismatches`、`missing_rule_revisions` 及判定明细。

---

## 7. HTTP 接口

| 方法与路径 | 说明 |
|---|---|
| `GET /` | 原接口，保持不变 |
| `POST /detection/events/{json,cef,leef,syslog}` | 摄入批次（json 传数组；文本格式可传字符串数组或每行一条纯文本） |
| `GET /detection/health` | 计数与资源上限 |
| `POST /detection/rules/reload` | 原子热更规则 |
| `GET /detection/rules` | 当前活动规则 |
| `GET /detection/alerts` / `GET /detection/alerts/{id}` | 告警查询 |
| `POST /detection/alerts/{id}/transition` | `{"status": ...}` 状态迁移 |
| `POST /detection/alerts/merge` | `{"parent_id","child_id"}` |
| `POST /detection/replay` | 重放校验 |
| `POST /detection/snapshot` | 写出本地快照 |

启动方式与原来一致：

```bash
uv run uvicorn main:app --reload
# 或：uv run fastapi run main.py
```

---

## 8. 验证方法

```bash
uv run pytest -q
```

测试以畸形事件归类、规则版本差异、并发投递、窗口边界、抑制优先级与重放为主：

- `tests/test_ingestion.py`：各来源归一、可区分拒绝原因、幂等、失败不污染状态；
- `tests/test_rules_compat.py`：v1 语义保留、v2 能力、明确拒绝、热更原子性；
- `tests/test_lifecycle_dedupe.py`：窗口边界、迟到折入、抑制不吞高优、状态机、
  旧告警绑定旧规则版本；
- `tests/test_concurrency.py`：同 id 并发恰好一次、计数无漂移、背压无部分状态；
- `tests/test_replay.py`：重放与原始一致、判定可追溯输入摘要与规则版本；
- `tests/test_api.py`：错误码归类与原 `/` 接口行为保持。

pytest 以 `--log-cli-level=INFO` 运行，日志中对每个事件打印
`event_id/source/severity/input_digest`，对每条判定打印
`rule@revision/signature/matched/alert/判定依据`；测试用例本身通过
`log_case(...)` 打印输入摘要。
