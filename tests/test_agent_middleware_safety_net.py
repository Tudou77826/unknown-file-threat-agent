"""SafetyNetMiddleware — the net around the tool execution chain.

背景：provider 偶发畸形工具调用曾让中间件链内抛 IndexError 直接杀死整案
（demo r5 benign-l1）。ToolNode 只兜"工具函数自身"的错，中间件 wrap 层的
意外异常没有兜底——安全网在最外层把它转为可观测错误，模型据此调整。
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from langchain_core.messages import ToolMessage

from threat_agent.agent_middleware import (
    BudgetExhausted,
    MiddlewareEvent,
    SafetyNetMiddleware,
)


def _request(name: str = "query_process_activities", call_id: str = "c1"):
    return SimpleNamespace(tool_call={"name": name, "args": {}, "id": call_id})


def test_unexpected_exception_becomes_observable_error():
    events: list[MiddlewareEvent] = []
    net = SafetyNetMiddleware(on_event=events.append)

    def handler(_request):
        raise IndexError("tuple index out of range")

    result = net.wrap_tool_call(_request(), handler)

    assert isinstance(result, ToolMessage)
    assert result.status == "error"
    assert result.tool_call_id == "c1"
    payload = json.loads(result.content)
    assert payload["error"] == "tool_chain_failed"
    assert payload["error_type"] == "IndexError"
    assert events and events[0].kind == "tool_chain_error"
    assert events[0].detail["error_type"] == "IndexError"


def test_budget_exhausted_passes_through():
    net = SafetyNetMiddleware()

    def handler(_request):
        raise BudgetExhausted("tool_calls", "预算耗尽")

    try:
        net.wrap_tool_call(_request(), handler)
    except BudgetExhausted:
        pass
    else:
        raise AssertionError("BudgetExhausted 必须穿透安全网（它是熔断信号）")


def test_normal_result_untouched():
    net = SafetyNetMiddleware()
    expected = ToolMessage(content="{}", tool_call_id="c1")
    assert net.wrap_tool_call(_request(), lambda _r: expected) is expected
