"""Last-resort net around the tool execution chain.

A tool function's own errors are converted to observations by the framework's
ToolNode, and business rejections are structured (boundary/budget). But an
unexpected exception raised inside a *middleware* wrap — or triggered through
one by a malformed provider tool call — propagates out of the tools task and
kills the whole case, taking a half-hour investigation with it. ``SafetyNetMiddleware``
sits outermost in the wrap chain and converts any such exception into an
error ``ToolMessage`` the model can observe and route around.

``BudgetExhausted`` is deliberately let through: it is the runner's stop
signal for the degradation path, not a failure.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from langchain.agents.middleware.types import (
    AgentMiddleware,
    ToolCallRequest,
)
from langchain_core.messages import AnyMessage, ToolMessage
from langgraph.types import Command

from .budget import BudgetExhausted
from .events import EventSink, MiddlewareEvent, null_sink


class SafetyNetMiddleware(AgentMiddleware):
    """Convert unexpected tool-chain exceptions into observable errors."""

    def __init__(self, *, on_event: EventSink | None = None):
        super().__init__()
        self.on_event = on_event or null_sink

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        try:
            return handler(request)
        except BudgetExhausted:
            raise
        except Exception as error:  # noqa: BLE001 — the net exists precisely here
            return self._error_result(request, error)

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        try:
            return await handler(request)
        except BudgetExhausted:
            raise
        except Exception as error:  # noqa: BLE001
            return self._error_result(request, error)

    def _error_result(
        self, request: ToolCallRequest, error: Exception
    ) -> ToolMessage | Command[Any]:
        tool_call = request.tool_call
        tool_name = str(tool_call.get("name") or "")
        call_id = str(tool_call.get("id") or "")
        self.on_event(
            MiddlewareEvent(
                "tool_chain_error",
                tool_name=tool_name,
                detail={
                    "tool_call_id": call_id,
                    "error_type": type(error).__name__,
                    "error_message": str(error)[:300],
                },
            )
        )
        payload = {
            "error": "tool_chain_failed",
            "error_type": type(error).__name__,
            "message": (
                f"工具执行链发生意外错误（{type(error).__name__}），本次调用作废；"
                "请检查参数后重试或换一种方式继续调查"
            ),
        }
        return ToolMessage(
            content=json.dumps(payload, ensure_ascii=False),
            tool_call_id=call_id,
            name=tool_name,
            status="error",
        )


__all__ = ["SafetyNetMiddleware"]
