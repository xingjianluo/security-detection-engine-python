"""服务入口（与此前相同的启动方式：``uvicorn main:app``）。

以持久化模式创建引擎：启动时自动从本地快照 + 流水恢复（重启接续），
运行期事件/告警/规则版本/去重与抑制锚点持续落本地，无需额外开关或
特殊调用。
"""

from detector.api import create_app

app = create_app(persist=True)


@app.get("/")
def read_root():
    return {"Hello": "World"}
