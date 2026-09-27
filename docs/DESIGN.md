# 本地安全事件检测与告警处置引擎 — 设计与使用说明

在既有 FastAPI 服务（`GET / -> {"Hello": "World"}`）上扩展，提供
本地存储 + 本地规则文件驱动的安全事件检测、告警生命周期与重放能力。

## 1. 总览

```
多来源事件 ──归一化──> 统一 Event ──规则判定(绑定版本)──> 告警生命周期
 generic_json            (显式拒绝       (v1/v2 兼容,        去重/合并/抑制/
 syslog_cef              可区分原因)      未知字段必拒绝)      状态机)
 alert_webhook                                                        │
                                                                     ▼
                                            append-only 流水 Journal（含输入摘要）
                                                                     │
                                            快照 Snapshot ◀── 重放 Replay（逐条核对）
```

模块：

| 模块 | 职责 |
|---|---|
| `detector/models.py` | 统一 `Event` / `Alert` / `Rule` / `JournalEntry`、时间解析、输入摘要 |
| `detector/errors.py` | 错误分类（每种拒绝有机器码 `reason`） |
| `detector/normalize.py` | 三种来源格式归一化 |
| `detector/rules.py` | v1/v2 规则加载、白名单校验、条件评估、判定轨迹 |
| `detector/store.py` | 线程安全内存存储 + 规则版本历史 + 快照导入导出 |
| `detector/alerts.py` | 状态机、去重/合并/抑制窗口、严重度升级 |
| `detector/engine.py` | 事务摄入、背压、判定编排、并发控制、重放 |
| `detector/persistence.py` | 原子快照、append-only JSONL 流水 |
| `detector/api.py` | FastAPI 路由 |

## 2. 事件模型

归一化后的统一模型（`detector.models.Event`）：

| 字段 | 说明 |
|---|---|
| `event_id` | 来源侧唯一标识，**幂等键** |
| `source` | `generic_json` / `syslog_cef` / `alert_webhook`（可用 `register_source` 扩展） |
| `event_type` / `severity` | 类型 / `info,low,medium,high,critical` |
| `occurred_at` | 事件发生时间（统一为 UTC 带时区） |
| `ingested_at` | 引擎接收时间 |
| `src_ip`,`dst_ip`,`user`,`host`,`action` | 通用实体字段 |
| `raw` | 原始负载（保真保留） |
| `digest` | 原始输入的 SHA-256 前 16 位摘要（稳定规范化 JSON 计算） |

支持的时间表达：ISO-8601（含 `Z`/偏移量/空格分隔）、epoch 秒；
整数型 epoch 按确定性阈值识别毫秒（≥1e12）/微秒（≥1e15）。

### 2.1 来源格式映射

**generic_json**：`event_id,type,severity,timestamp,src_ip,dst_ip,user,host,action`

**syslog_cef**（CEF 风格）：

| CEF 字段 | 统一字段 | 备注 |
|---|---|---|
| `id` | event_id | 必填 |
| `signatureId` 或 `deviceProduct` | event_type | 至少一个 |
| `rt` | occurred_at | epoch 毫秒或 ISO |
| `severity` | severity | 整数 0–10：0–3 low，4–6 medium，7–8 high，9–10 critical |
| `src`/`dst`/`suser`/`dhost`(或 `shost`)/`act` | 同名实体 | |

**alert_webhook**：`uuid,alert_type,level(1–5),created_at,source_ip,account,hostname`

## 3. 拒绝原因码（不会静默丢弃）

| reason 码 | 触发场景 |
|---|---|
| `missing_field` | 必填字段缺失或为空 |
| `invalid_severity` | 严重级别无法识别 |
| `malformed_payload` | 单条负载不是 JSON 对象 |
| `invalid_timestamp` | 时间格式非法 |
| `future_timestamp` | 事件时间超出时钟漂移容忍 |
| `stale_event` | 事件时间早于迟到窗口 |
| `unknown_source` | 未注册的来源格式 |
| `batch_too_large` | 批次条数超 `max_batch_size`（**整批拒绝**） |
| `batch_oversize_bytes` | 批次字节超限（**整批拒绝**） |
| `event_oversize_bytes` | 单事件字节超限（**整批拒绝**） |
| `backpressure_rejected` / `backpressure_timeout` | 积压超限拒绝 / delay 策略等待超时 |
| `duplicate_event` | 显式幂等冲突（摄入接口对重复投递返回 `dedup_hit=true`，不报错） |
| `unsupported_rule_version` / `unsupported_rule_field` / `unsupported_rule_semantics` | 规则版本/未知字段/未知操作符 |
| `illegal_state_transition` | 告警状态机非法跳转 |
| `replay_mismatch` | 重放结论与流水不一致 |
| `retention_limit_rejected` | 保留上限触顶且策略为 `reject`，新进入的历史被拒绝 |
| `archive_error` | 归档写入/读取失败（显式报错，不留半成品） |

事务语义：批次级违规（超限、背压）在任何写入前判定，**整批不留状态**；
单条事件违规只拒绝该条，同批其它事件正常提交。

## 4. 规则格式与兼容范围

### 4.1 v2（当前格式）

```json
{
  "format_version": 2,
  "revision": 7,
  "rules": [
    {
      "id": "r2", "name": "…", "event_type": "login", "severity": "high",
      "conditions": {"all": [
        {"field": "src_ip", "op": "prefix", "value": "10."},
        {"any": [
          {"field": "user", "op": "in", "value": ["admin", "root"]},
          {"field": "severity", "op": "gte", "value": "high"}]}]},
      "dedup_window_s": 300,
      "correlation_key": ["src_ip", "user"],
      "merge_key": ["rule_id", "src_ip"],
      "suppress": {"window_s": 600, "max_severity": "medium"},
      "enabled": true
    }
  ]
}
```

- 条件树：`all` / `any` / `not` 组合；叶子 `{field, op, value}`。
- 可访问字段：`event_id,event_type,severity,src_ip,dst_ip,user,host,action`
  （规则键还允许 `rule_id` 占位）。
- 操作符：`eq,ne,in,prefix,regex,gte,lte`（severity 的 gte/lte/eq 按级别比较）。
- 未知字段（顶层、条件叶子、suppress、键列表）一律
  `unsupported_rule_field` 拒绝；未知操作符 `unsupported_rule_semantics`；
  不存在静默忽略。
- `severity` 是**基线门槛**：事件级别低于它规则不命中，从而继续尝试
  规则列表中的下一条（高基线规则不会抢走低级别事件）。
- 告警严重度 = max(规则基线, 事件严重度)。

### 4.2 v1（旧格式，按原语义继续生效）

```json
{"id":"old", "event_type":"login_failure",
 "min_severity":"medium", "window_seconds":120, "enabled": true}
```

加载时归一为内部表示：`min_severity` → 严重度基线（+gte 条件），
`window_seconds` → `dedup_window_s`，`format_version=1`。
v2 文档内也允许内嵌 `version:1` 条目。

### 4.3 版本演进与可复现

- `revision` 单调递增；发布只追加到规则历史，旧 revision 永久保留
  （`store.rules_at(rev)`）。
- **告警绑定命中时刻的 `(rule_version, rule_revision)`**，规则更新
  不改写任何历史告警；其 `trace.checks` 保留命中时的逐步判定依据。
- 重放时规则文档按发布时记录的 `document_digest` 从 `rules_dir` 找回，
  找不到即显式失败，杜绝用被改过的规则“复现”旧结论。

## 5. 告警状态机与窗口

### 5.1 状态

```
OPEN ──ack──> ACKNOWLEDGED ──resolve──> RESOLVED（终态）
  │                │  ▲                    │
  └─suppress┐      └──┘ reopen(被抑制恢复)  终态不可跳转
            ▼
        SUPPRESSED ──窗口到期──> OPEN
任意活动态 ──显式合并──> MERGED（终态，merged_into 指向主告警）
```

- 非法跳转返回 `illegal_state_transition`；同态跳转（如 resolve 后再
  resolve）是幂等 no-op，支持客户端重试。
- 被抑制告警：`state=suppressed` 且 `suppressed_by` 指向压制者；
  被合并告警：`state=merged` 且 `merged_into` 指向主告警——归属可区分。

### 5.2 去重窗口（确定性）

- 锚定主告警**首个事件**：事件时间在 `[first, first+dedup_window_s)`
  内并入主告警（计数 +1，`event_digests` 记录全部输入摘要）；
- 迟到/乱序事件在 `[first-window, first)` 内同样并入，避免重复告警；
- 恰好落在边界（±window）确定性地开启新窗口，窗口不会因后续事件无限续用；
- 同一 `event_id`/digest 无论如何重试只计一次。

### 5.3 抑制窗口

- 命中带 `suppress` 的规则后，从最近事件时间起的半开窗口
  `[last, last+window)` 内：候选告警严重度 `<= max_severity`
  **且** `<= 压制者自身严重度` 才会被抑制 ——
  **低优先级抑制绝不吞掉更高优先级告警**。
- 抑制到期由 `POST /api/v1/alerts/tick-suppress-expiry`（或
  `engine.suppress_expired_tick()`）驱动恢复 OPEN（本地模拟，无后台线程）。

## 6. 并发、背压与失败安全

- 引擎内单一 `RLock` 串行化摄入 / 规则发布 / 状态变更 / 查询；
  存储读操作返回深拷贝快照。无半更新批次、无计数漂移、无状态互相覆盖。
- 事件幂等键 `event_id`：`put_event_if_absent` 原子判定，并发投递
  只有一个胜出，其余返回 `dedup_hit=true`（64 线程并发测试验证）。
- 背压：`max_inflight_events` 限制在途事件；`on_backpressure=reject`
  时超 限返回 503 `backpressure_rejected` 且不写入；`delay` 时等待
  积压回落（30s 超时 -> `backpressure_timeout`）。许可在 finally
  释放，处理失败不残留占用。
- 快照：临时文件 + fsync + `os.replace` 原子替换，失败保留旧文件。
- 流水：append-only JSONL，每条 fsync；损坏行显式 `SnapshotError`。

## 7. 流水与重放（可追溯）

每条状态变更都产生一条流水（单调 `seq`），关键载荷：

- `rules_published`：revision、rule_ids、**规则原文**（自包含，恢复/
  重放不依赖 `rules_dir` 当前内容）、`document_digest`
- `event_accepted`：event_id、`digest`、**完整归一事件**
- `alert_opened` / `alert_suppressed` / `alert_dedup`：alert_id、
  `rule_id/rule_version/rule_revision`、`suppressed_by`、逐条 `checks`
- `event_no_match` 及 ack/resolve/merge/reopen 等

重放（`engine.replay(journal_path, config)`）：
按 seq 重建规则历史 → 逐条重新判定 → 与原始流水比对
（结论类型、命中规则版本、抑制归属、输入摘要），任何不一致抛
`replay_mismatch`。`POST /api/v1/replay` 返回逐条报告。
快照恢复使用 `engine.restore_snapshot()` / `replay_from_snapshot()`。

## 8. 重启接续（persist 默认开启）

`Config.persist=True`（默认）时，相同的启动方式
（`uvicorn main:app` → `create_app()` → `build_engine()`）自动完成：

1. **写入侧**：每条流水 append 到 `journal_path`（fsync）；每
   `snapshot_every` 条流水自动原子落一次快照。
2. **恢复侧**：启动时先恢复快照（事件/告警/规则历史/幂等锚点/seq），
   再按序重放流水文件中 `seq > 快照seq` 的尾部条目，重建最新状态。

恢复后无需任何额外开关或特殊调用：

- 重启前已处理的事件/告警/当前生效规则版本可继续查询；
- 重复投递已处理事件仍返回 `dedup_hit=true`，不重复计数、不重复开告警
  （幂等锚点随快照持久化）；
- 去重/抑制窗口锚点（活动告警及其窗口参数）随状态恢复，抑制结论延续；
- 规则目录内容未变时自动加载幂等，**不产生多余 revision**；
- 流水 `seq` 单调不回退，重启后续写不冲突；
- 可随时 `POST /api/v1/replay` 对这段历史做重放核对，结论与当初一致。

`persist=False`（显式构造 `Engine(cfg)` 的默认）保持纯内存行为，
既有测试与嵌入式用法不受影响。

## 9. 有界保留与归档

### 9.1 保留上限与两种策略

`max_retained_events` / `max_retained_alerts` / `max_retained_journal`
（0=不限制）任一触顶时按 `on_retention_exceeded` 处置：

- `reject`：新事件被拒绝，单条结论 `reason=retention_limit_rejected`
  （与背压/校验拒绝可区分）；**重复投递已处理事件仍判 dedup**，
  不算新进入。该策略下需运维介入（调大上限或改 evict）才能继续写入。
- `evict`（默认）：淘汰最旧历史，摄入正常返回，响应体 `evicted`
  数组列出本批淘汰明细（`reason=retention_evicted`），两种结果
  从返回即可区分。

### 9.2 淘汰只影响历史明细

- 事件：淘汰最旧明细，但留下 **幂等锚点**（event_id→digest），
  重复投递仍判已处理，不会把旧事件判成新事件；
- 告警：**只淘汰终态**（resolved/merged）；活动告警、去重/抑制窗口
  锚点绝不淘汰——抑制结论与计数不漂移（活动告警可暂时超出上限，
  锚点正确性优先于上限）；
- 流水：淘汰最旧条目。persist 模式下淘汰前先落快照，恢复不依赖
  已淘汰的流水段，重启状态一致。

### 9.3 归档（`archive_enabled` 默认开启）

被淘汰的事件/告警/流水追加写入 `archive_dir/archive.jsonl`
（每条记录带 `archived_at` 与 `record_kind`，边界清楚）：

- **先写归档、后改状态**：归档写失败抛 `archive_error`，热状态
  原封不动、不留半成品；归档读损坏同样显式报错；
- 归档写盘在引擎锁外进行，不阻塞正常摄入判定；
- 日常查询（事件/告警/流水/重放）**不加载归档**；
- 完整重放或用归档重建状态时显式纳入：
  `replay(journal_path, cfg, include_archive=True)` 或
  `POST /api/v1/replay?include_archive=true`——按 `seq` 归并去重后
  逐条核对，结论与无淘汰时一致，每条判定仍可追溯到命中规则版本
  与输入摘要。流水被截断后不带归档直接重放会显式失败
  （`replay_mismatch`），不会给出静默的错误结论。

## 10. 配置项（`detector/config.py`）

| 配置 | 默认 | 含义 |
|---|---|---|
| `max_batch_size` | 1000 | 单批最大条数（超过整批拒绝） |
| `max_batch_bytes` | 2 MiB | 单批最大字节 |
| `max_event_bytes` | 64 KiB | 单事件最大字节 |
| `max_inflight_events` | 10000 | 背压阈值 |
| `on_backpressure` | `reject` | `reject` / `delay` |
| `max_out_of_order_s` | 3600 | 可接受迟到窗口，更早事件判 `stale_event` |
| `future_tolerance_s` | 300 | 允许的未来时钟漂移 |
| `default_dedup_window_s` | 300 | 规则未声明时的去重窗口 |
| `supported_rule_versions` | (1,2) | 接受的规则格式版本 |
| `rules_dir` | `rules` | 启动自动加载与重放取规则原文的目录 |
| `persist` | `True` | 启动自动从 快照+流水 恢复（重启接续） |
| `journal_path` / `snapshot_path` | `data/…` | 流水/快照位置（`data_dir` 覆盖时自动锚定其下） |
| `snapshot_every` | 1000 | 每 N 条流水自动落快照（0 关闭） |
| `max_retained_events` | 0 | 事件明细保留上限（条，0=不限） |
| `max_retained_alerts` | 0 | 告警明细保留上限（条，0=不限；活动告警不淘汰） |
| `max_retained_journal` | 0 | 判定流水保留上限（条，0=不限） |
| `on_retention_exceeded` | `evict` | `evict`（淘汰最旧）/ `reject`（拒绝新进入） |
| `archive_enabled` | `True` | 淘汰的历史是否落归档 |
| `archive_dir` | `data/archive` | 归档目录（日常查询不加载） |

## 11. HTTP 接口

| 方法/路径 | 说明 |
|---|---|
| `GET /` | 既有接口，保持 `{"Hello":"World"}` |
| `GET /health` | 存活与统计 |
| `POST /api/v1/events` | 批次摄入，body `{source, events:[…]}`；响应含 `accepted/rejected/evicted` |
| `GET /api/v1/events/{id}` | 事件查询 |
| `POST /api/v1/rules` | 发布规则文档 `{document:{…}}`，返回新 revision |
| `GET /api/v1/rules` | 当前生效规则集与 revision |
| `GET /api/v1/alerts?state=` | 告警列表（可按状态过滤） |
| `GET /api/v1/alerts/{id}` | 告警详情（含版本绑定、checks、归属） |
| `POST /api/v1/alerts/{id}/acknowledge` / `/resolve` / `/reopen` | 状态跳转 |
| `POST /api/v1/alerts/tick-suppress-expiry` | 抑制到期恢复 |
| `GET /api/v1/journal` | 流水 |
| `POST /api/v1/snapshot` | 原子写快照 |
| `POST /api/v1/replay` | 流水重放并返回逐条核对报告；`?include_archive=true` 显式纳入归档 |

错误响应统一为 `{"error":{"code":…,"message":…}}`
（422 校验类 / 503 背压 / 404 未找到）。

## 12. 启动与验证

```bash
uv sync --group dev
uv run uvicorn main:app --port 8000        # 启动方式与既有服务一致（默认持久化+恢复）
uv run pytest -q                            # 40 个单测（含摘要/依据日志）
```

快速手工验证：

```bash
curl -s localhost:8000/                                   # {"Hello":"World"}
curl -s -XPOST localhost:8000/api/v1/events -H 'content-type: application/json' -d '{
  "source":"generic_json",
  "events":[{"event_id":"e1","type":"ssh_auth_failure","severity":"high",
             "timestamp":"2026-09-22T11:00:00Z","src_ip":"10.1.1.1","user":"bob"}]}'
curl -s localhost:8000/api/v1/alerts | python -m json.tool
```

重启接续手工验证（相同启动方式跑两次，无需额外开关）：

```bash
uv run uvicorn main:app --port 8000 &        # 第一次运行，摄入若干事件后杀掉
uv run uvicorn main:app --port 8000 &        # 第二次运行：
curl -s localhost:8000/api/v1/events/e1      # 重启前事件仍可查
curl -s -XPOST localhost:8000/api/v1/events -H 'content-type: application/json' -d '{
  "source":"generic_json","events":[{"event_id":"e1","type":"ssh_auth_failure",
  "severity":"high","timestamp":"2026-09-22T11:00:00Z","src_ip":"10.1.1.1","user":"bob"}]}'
# -> dedup_hit=true，不重复计数
curl -s -XPOST localhost:8000/api/v1/replay  # 对这段历史重放核对，结论一致
```

保留与归档验证（配置 `max_retained_events` 等上限后持续投递）：
`GET /health` 的 `stats` 可见 `event_tombstones` 与 `retention` 策略；
摄入响应 `evicted` 列出淘汰明细；`data/archive/archive.jsonl` 存归档；
`POST /api/v1/replay?include_archive=true` 做含归档的完整重放。

测试覆盖（`tests/`）：畸形事件归类、时间非法/迟到/未来、批次上限、
v1/v2 兼容与显式拒绝、历史版本绑定、窗口边界（299/300s）、抑制优先级、
合并归属、乱序计数、64 线程同 id 并发只生效一次、3200 并发事件无计数
漂移、背压无部分写入、流水重放一致与篡改检测、HTTP 全流程、
**重启接续（状态/去重/抑制锚点/重放一致）**、**保留上限下 reject 与
evict 两条路径**、**淘汰后锚点不漂移与归档重放一致**、归档损坏显式报错。
