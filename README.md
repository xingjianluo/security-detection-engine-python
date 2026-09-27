# security-detection-engine-python-bootstrap

本地安全事件检测与告警处置服务（FastAPI）。在原有
`GET / -> {"Hello": "World"}` 服务基础上扩展，不改变既有接口与启动方式。

## 快速开始

```bash
uv sync --group dev
uv run uvicorn main:app --port 8000   # 自动加载 rules/*.json
uv run pytest -q                       # 运行测试（日志打印输入摘要与判定依据）
```

## 能力一览

- 三种来源事件格式（generic_json / syslog_cef / alert_webhook）归一化，
  字段缺失、时间非法、超限批次按可区分原因码拒绝，不静默丢弃；
- 幂等摄入：相同 `event_id` 的重试/并发投递只生效一次；
- 本地规则文件 v1/v2 双版本兼容，未知字段/操作符显式拒绝；
  告警绑定命中时的规则版本，规则更新不改写历史结论；
- 告警状态机（open/ack/resolved/suppressed/merged）、确定性窗口的
  去重/抑制/合并，低优先级抑制不吞高优先级告警；
- 背压与资源上限（拒绝或延迟），失败不留部分状态；
- append-only 流水 + 原子快照，重放结果与原始处理逐条核对一致，
  每条判定可追溯到规则版本与输入摘要；
- **重启接续**：默认持久化，相同启动方式重启后事件/告警/规则版本/
  去重与抑制锚点继续生效，重复投递仍判已处理，无需额外开关；
- **有界保留**：事件/告警/流水可配置上上限，触顶按策略拒绝
  （`retention_limit_rejected`）或淘汰最旧（响应 `evicted` 可见），
  淘汰不动幂等/抑制锚点与活动告警；
- **归档与按需重放**：淘汰的历史落本地归档（`data/archive/`），
  日常查询不加载；`POST /api/v1/replay?include_archive=true`
  显式纳入归档做完整重放，结论与无归档时一致。

详见 [docs/DESIGN.md](docs/DESIGN.md)（事件模型、规则格式、状态机、
配置项与验证方法）。
