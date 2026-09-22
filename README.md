# Security Detection Engine (Python bootstrap)

原有 FastAPI 服务保持可用（`GET /` → `{"Hello": "World"}`），并在其上扩展了
本地安全事件检测与告警处置能力：多来源事件归一、版本化规则、幂等摄入、
去重/抑制、告警生命周期、背压、快照与可追溯重放。

## 快速开始

```bash
uv sync
cp data/rules.example.json data/rules.json   # 可选：预置本地规则
uv run uvicorn main:app --reload
curl http://127.0.0.1:8000/                  # 原接口不变
curl http://127.0.0.1:8000/detection/health
```

## 测试

```bash
uv run pytest -q
```

## 文档

事件模型、规则格式与兼容范围、状态机、配置项与验证方法见
[`docs/DETECTION.md`](docs/DETECTION.md)。
