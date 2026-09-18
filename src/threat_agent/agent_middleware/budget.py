"""Run-scoped multi-dimension budget middleware.

Three dimensions with two different exhaustion semantics (inherited from the
investigation system the package was extracted from):

- Tool-call budget: exhausted calls are denied with a structured error tool
  result and the loop continues — the model sees the denial and can wrap up.
- Model-call and total-token budgets: exhaustion is a stop signal. The
  middleware raises ``BudgetExhausted`` out of the agent invocation; the
  business side catches it at the call boundary and runs its own degradation
  path (for example composing a report from whatever was already queried).

Counters live in middleware-extended agent state so they are checkpointed
with the graph. Decisions are delegated to the injected ``BudgetPolicy``
(protocol); the default ``LimitsBudgetPolicy`` enforces plain numeric
limits.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, TypeVar

from langchain.agents.middleware.types import (
    AgentMiddleware,
    ExtendedModelResponse,
    ModelRequest,
    PrivateStateAttr,
    ToolCallRequest,
    add_messages,
)
from langchain_core.messages import AnyMessage, ToolMessage
from langgraph.types import Command
from typing_extensions import Annotated, NotRequired, Required, TypedDict

from .events import EventSink, MiddlewareEvent, null_sink

ContextT = TypeVar("ContextT")
ResponseT = TypeVar("ResponseT")


def _parallel_max(current: int | None, incoming: int) -> int:
    """Parallel tool calls complete within one step, each branch having read
    the same base counter and added its own delta; max() reconstructs the
    sequential semantics without double counting."""
    return max(current or 0, incoming)



class BudgetState(TypedDict, total=False):
    messages: Required[Annotated[list[AnyMessage], add_messages]]
    budget_model_calls: NotRequired[Annotated[int, PrivateStateAttr, _parallel_max]]
    budget_tool_calls: NotRequired[Annotated[int, PrivateStateAttr, _parallel_max]]
    budget_total_tokens: NotRequired[Annotated[int, PrivateStateAttr, _parallel_max]]


class BudgetExhausted(RuntimeError):
    """Stop signal: a budget dimension no longer allows model calls."""

    def __init__(self, dimension: str, message: str):
        super().__init__(message)
        self.dimension = dimension


class BudgetUsage:
    __slots__ = ("model_calls", "tool_calls", "total_tokens")

    def __init__(self, model_calls: int, tool_calls: int, total_tokens: int):
        self.model_calls = model_calls
        self.tool_calls = tool_calls
        self.total_tokens = total_tokens


class BudgetPolicy(Protocol):
    """Business-injectable budget decisions."""

    def allow_model_call(self, usage: BudgetUsage) -> None:
        """Raise ``BudgetExhausted`` when the model must not be called again."""
        ...

    def allow_tool_call(self, usage: BudgetUsage) -> None:
        """Raise ``BudgetExhausted`` when this tool call must be denied."""
        ...


class LimitsBudgetPolicy:
    """Default policy: independent numeric limits, ``None`` means unlimited."""

    def __init__(
        self,
        *,
        max_model_calls: int | None = None,
        max_tool_calls: int | None = None,
        max_total_tokens: int | None = None,
    ):
        self.max_model_calls = max_model_calls
        self.max_tool_calls = max_tool_calls
        self.max_total_tokens = max_total_tokens

    def allow_model_call(self, usage: BudgetUsage) -> None:
        if self.max_model_calls is not None and usage.model_calls >= self.max_model_calls:
            raise BudgetExhausted(
                "model_calls", f"模型调用预算已耗尽（上限 {self.max_model_calls} 次）"
            )
        if self.max_total_tokens is not None and usage.total_tokens >= self.max_total_tokens:
            raise BudgetExhausted(
                "total_tokens", f"token 预算已耗尽（上限 {self.max_total_tokens}）"
            )

    def allow_tool_call(self, usage: BudgetUsage) -> None:
        if self.max_tool_calls is not None and usage.tool_calls >= self.max_tool_calls:
            raise BudgetExhausted(
                "tool_calls", f"工具调用预算已耗尽（上限 {self.max_tool_calls} 次）"
            )


def _usage_from_state(state: Any) -> BudgetUsage:
    def counter(key: str) -> int:
        value = state.get(key) if hasattr(state, "get") else getattr(state, key, None)
        return value if isinstance(value, int) else 0

    return BudgetUsage(
        model_calls=counter("budget_model_calls"),
        tool_calls=counter("budget_tool_calls"),
        total_tokens=counter("budget_total_tokens"),
    )


def _usage_total(usage: Any) -> int:
    if isinstance(usage, dict):
        tokens = usage.get("total_tokens")
        if isinstance(tokens, int):
            return tokens
    return 0


def _response_total_tokens(response: Any) -> int:
    """Extract total tokens from a raw AIMessage or a ModelResponse wrapper."""

    if hasattr(response, "usage_metadata"):
        return _usage_total(response.usage_metadata)
    result = getattr(response, "result", None)
    if isinstance(result, list):
        return sum(_usage_total(getattr(message, "usage_metadata", None)) for message in result)
    return 0


def _budget_denial_message(tool_call: dict[str, Any], exhausted: BudgetExhausted) -> ToolMessage:
    payload = {
        "error_type": "BudgetDenied",
        "error_dimension": exhausted.dimension,
        "error_message": str(exhausted),
    }
    return ToolMessage(
        content=json.dumps(payload, ensure_ascii=False),
        tool_call_id=str(tool_call.get("id") or ""),
        name=str(tool_call.get("name") or ""),
        status="error",
    )


class BudgetMiddleware(AgentMiddleware[BudgetState, ContextT, ResponseT]):
    """Enforce run-scoped budgets over model calls, tool calls and tokens."""

    state_schema = BudgetState  # type: ignore[assignment]

    def __init__(
        self,
        policy: BudgetPolicy | None = None,
        *,
        max_model_calls: int | None = None,
        max_tool_calls: int | None = None,
        max_total_tokens: int | None = None,
        on_event: EventSink | None = None,
    ):
        super().__init__()
        if policy is None:
            policy = LimitsBudgetPolicy(
                max_model_calls=max_model_calls,
                max_tool_calls=max_tool_calls,
                max_total_tokens=max_total_tokens,
            )
        self.policy = policy
        self.on_event = on_event or null_sink

    def wrap_model_call(
        self,
        request: ModelRequest,
        handler: Callable[[ModelRequest], Any],
    ) -> Any:
        usage = _usage_from_state(request.state)
        try:
            self.policy.allow_model_call(usage)
        except BudgetExhausted as exhausted:
            self._emit_exhausted(exhausted)
            raise
        response = handler(request)
        tokens = _response_total_tokens(response)
        return ExtendedModelResponse(
            model_response=response,
            command=Command(update={
                "budget_model_calls": usage.model_calls + 1,
                "budget_total_tokens": usage.total_tokens + tokens,
            }),
        )

    async def awrap_model_call(
        self,
        request: ModelRequest,
        handler: Callable[[ModelRequest], Awaitable[Any]],
    ) -> Any:
        usage = _usage_from_state(request.state)
        try:
            self.policy.allow_model_call(usage)
        except BudgetExhausted as exhausted:
            self._emit_exhausted(exhausted)
            raise
        response = await handler(request)
        tokens = _response_total_tokens(response)
        return ExtendedModelResponse(
            model_response=response,
            command=Command(update={
                "budget_model_calls": usage.model_calls + 1,
                "budget_total_tokens": usage.total_tokens + tokens,
            }),
        )

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        usage = _usage_from_state(request.state)
        try:
            self.policy.allow_tool_call(usage)
        except BudgetExhausted as exhausted:
            self.on_event(
                MiddlewareEvent(
                    "budget_denied",
                    tool_name=str(request.tool_call.get("name") or ""),
                    detail={
                        "error_dimension": exhausted.dimension,
                        "tool_call_id": str(request.tool_call.get("id") or ""),
                    },
                )
            )
            return _budget_denial_message(request.tool_call, exhausted)
        result = handler(request)
        update = dict(result.update) if isinstance(result, Command) else {}
        update["budget_tool_calls"] = usage.tool_calls + 1
        if isinstance(result, Command):
            return Command(update=update)
        return Command(update={"messages": [result], "budget_tool_calls": usage.tool_calls + 1})

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        usage = _usage_from_state(request.state)
        try:
            self.policy.allow_tool_call(usage)
        except BudgetExhausted as exhausted:
            self.on_event(
                MiddlewareEvent(
                    "budget_denied",
                    tool_name=str(request.tool_call.get("name") or ""),
                    detail={
                        "error_dimension": exhausted.dimension,
                        "tool_call_id": str(request.tool_call.get("id") or ""),
                    },
                )
            )
            return _budget_denial_message(request.tool_call, exhausted)
        result = await handler(request)
        update = dict(result.update) if isinstance(result, Command) else {}
        update["budget_tool_calls"] = usage.tool_calls + 1
        if isinstance(result, Command):
            return Command(update=update)
        return Command(update={"messages": [result], "budget_tool_calls": usage.tool_calls + 1})

    def _emit_exhausted(self, exhausted: BudgetExhausted) -> None:
        self.on_event(
            MiddlewareEvent(
                "budget_exhausted",
                detail={"error_dimension": exhausted.dimension},
            )
        )


__all__ = [
    "BudgetExhausted",
    "BudgetMiddleware",
    "BudgetPolicy",
    "BudgetState",
    "BudgetUsage",
    "LimitsBudgetPolicy",
]
