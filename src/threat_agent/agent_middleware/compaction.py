"""Deterministic tool-result downsizing middleware.

Complements the official ``SummarizationMiddleware`` rather than replacing
it. The official middleware compacts whole histories once a token or
message threshold is crossed; this middleware downsizes each tool result
deterministically at insertion time through an injected domain-aware
``Reducer``, so history grows slowly from the first round. The full
payload is never lost programmatically: the original content is preserved
in the message ``artifact`` (and, in business bindings, in the run's typed
ledger).

Reduction is best-effort: if the reducer raises, the original message
passes through unchanged and a ``reducer_error`` event is emitted.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, TypeVar

from langchain.agents.middleware.types import (
    AgentMiddleware,
    ToolCallRequest,
)
from langchain_core.messages import AnyMessage, BaseMessage, ToolMessage
from langgraph.types import Command

from .events import EventSink, MiddlewareEvent, null_sink

ContextT = TypeVar("ContextT")
ResponseT = TypeVar("ResponseT")

UNREDUCED_ARTIFACT_KEY = "unreduced_content"


class Reducer(Protocol):
    """Domain-aware downsizing contract: full result in, reduced result out."""

    def reduce(self, tool_name: str, result: Any) -> Any:
        ...


def _as_message_list(value: Any) -> list[AnyMessage]:
    if value is None:
        return []
    # BaseMessage, not AnyMessage: the latter is a subscripted alias and
    # cannot be used with isinstance.
    if isinstance(value, BaseMessage):
        return [value]
    return list(value)


def _reduce_message(
    message: ToolMessage, tool_name: str, reducer: Reducer
) -> ToolMessage:
    if not isinstance(message.content, str):
        return message
    try:
        payload = json.loads(message.content)
    except ValueError:
        return message
    if not isinstance(payload, dict):
        return message
    try:
        reduced = reducer.reduce(tool_name, payload)
    except Exception:
        # Downsizing is an optimization; never fail the tool call over it.
        return message
    if not isinstance(reduced, dict) or reduced == payload:
        return message
    artifact = message.artifact if isinstance(message.artifact, dict) else {}
    artifact = {**artifact, UNREDUCED_ARTIFACT_KEY: message.content}
    return ToolMessage(
        content=json.dumps(reduced, ensure_ascii=False),
        tool_call_id=message.tool_call_id,
        name=message.name,
        status=message.status,
        artifact=artifact,
    )


class ReducerMiddleware(AgentMiddleware):
    """Downsize every tool result before it enters the conversation."""

    def __init__(self, reducer: Reducer, *, on_event: EventSink | None = None):
        super().__init__()
        self.reducer = reducer
        self.on_event = on_event or null_sink

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        tool_call = request.tool_call
        tool_name = str(tool_call.get("name") or "")
        call_id = str(tool_call.get("id") or "")
        result = handler(request)
        return self._reduced_result(tool_name, call_id, result)

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        tool_call = request.tool_call
        tool_name = str(tool_call.get("name") or "")
        call_id = str(tool_call.get("id") or "")
        result = await handler(request)
        return self._reduced_result(tool_name, call_id, result)

    def _reduced_result(
        self,
        tool_name: str,
        call_id: str,
        result: ToolMessage | Command[Any],
    ) -> ToolMessage | Command[Any]:
        if isinstance(result, Command):
            update = dict(result.update or {})
            messages = _as_message_list(update.get("messages"))
        else:
            update = {}
            messages = [result]

        reduced: list[AnyMessage] = []
        changed = False
        for message in messages:
            if (
                isinstance(message, ToolMessage)
                and message.tool_call_id == call_id
                and isinstance(message.content, str)
            ):
                before = message.content
                message = _reduce_message(message, tool_name, self.reducer)
                if message.content != before:
                    changed = True
            reduced.append(message)

        if changed:
            self.on_event(
                MiddlewareEvent(
                    "reducer_applied",
                    tool_name=tool_name,
                    detail={"tool_call_id": call_id},
                )
            )
        if isinstance(result, Command):
            if changed:
                update["messages"] = reduced
            return Command(update=update)
        return reduced[0] if reduced else result


__all__ = ["Reducer", "ReducerMiddleware", "UNREDUCED_ARTIFACT_KEY"]
