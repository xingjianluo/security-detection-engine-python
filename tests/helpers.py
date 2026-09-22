"""测试辅助：统一打印输入摘要与判定依据。"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("detector.tests")


def log_judgement(input_payload: Any, result: Any, *, trace: Any = None) -> None:
    """打印输入摘要（digest）与判定依据（命中规则/原因/checks）。"""
    digest = None
    if isinstance(input_payload, dict):
        from detector.models import input_digest

        digest = input_digest(input_payload)
    checks = getattr(trace, "checks", None)
    log.info(
        "判定输入摘要=%s 结论=%s 依据=%s",
        digest,
        result,
        checks,
    )


def event_payload(eid="e1", **over):
    from detector.models import utcnow

    base = {
        "event_id": eid,
        "type": "login",
        "severity": "high",
        "timestamp": utcnow().isoformat(),
        "src_ip": "10.0.0.1",
        "user": "bob",
    }
    base.update(over)
    return base
