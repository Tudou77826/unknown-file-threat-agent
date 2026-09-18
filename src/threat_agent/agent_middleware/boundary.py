"""Capability-based tool-call boundary as an agent middleware.

Every tool call passes the same gate: the injected ``ToolBoundary`` policy
authorizes the call before execution and validates the resulting
``ToolMessage`` before it may enter the conversation. Rejections are
structured (stable error code plus resource identifiers) and are returned
to the model as error tool results — a boundary denial is never disguised
as an empty query result, and unauthorized object content never enters
model-visible message content.

The middleware is domain-agnostic: authorization semantics live entirely
in the policy. An opaque ledger dictionary is threaded through
middleware-extended agent state so policy bookkeeping (for example
run-authorized reference sets) is checkpointed with the graph.

Implementation notes (verified against langchain 1.2):

- ``wrap_tool_call`` sees the tool result as a serialized ``ToolMessage``
  (``content`` plus the optional structured ``artifact``), not the typed
  return value. Policies that need typed validation must work from the
  serialized form.
- State updates are returned as ``Command(update=...)`` so the ledger and
  the tool message land in the same state transition.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Protocol, TypeVar, runtime_checkable

from langchain.agents.middleware.types import (
    AgentMiddleware,
    PrivateStateAttr,
    ToolCallRequest,
    add_messages,
)
from langchain_core.messages import AnyMessage, BaseMessage, ToolMessage
from langgraph.types import Command
from pydantic import BaseModel, Field
from typing_extensions import Annotated, NotRequired, Required, TypedDict

from .events import EventSink, MiddlewareEvent, null_sink

ContextT = TypeVar("ContextT")
ResponseT = TypeVar("ResponseT")


def _keep_latest(current: dict[str, Any] | None, incoming: dict[str, Any]) -> dict[str, Any]:
    """Parallel tool calls may complete within one step; every write carries
    the same middleware-owned ledger object, so last-write-wins is identity
    here while keeping the state key parallel-safe."""
    return incoming


class BoundaryState(TypedDict, total=False):
    messages: Required[Annotated[list[AnyMessage], add_messages]]
    boundary_ledger: NotRequired[Annotated[dict[str, Any], PrivateStateAttr, _keep_latest]]


class BoundaryRejection(BaseModel):
    """Structured rejection: identifiers only, never unauthorized content."""

    code: str
    tool_name: str
    message: str
    resource_refs: list[str] = Field(default_factory=list)

    def as_tool_message(self, tool_call_id: str) -> ToolMessage:
        payload = {
            "error_type": "BoundaryDenied",
            "error_code": self.code,
            "error_message": self.message,
            "resource_refs": self.resource_refs,
        }
        return ToolMessage(
            content=json.dumps(payload, ensure_ascii=False),
            tool_call_id=tool_call_id,
            name=self.tool_name,
            status="error",
        )


class BoundaryViolationError(RuntimeError):
    """Raised by a ToolBoundary to signal a structured rejection."""

    def __init__(self, rejection: BoundaryRejection):
        super().__init__(rejection.message)
        self.rejection = rejection

    @property
    def code(self) -> str:
        return self.rejection.code


@runtime_checkable
class ToolBoundary(Protocol):
    """Domain-agnostic authorization contract; policies are injected."""

    def authorize(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        ledger: dict[str, Any],
    ) -> None:
        """Raise ``BoundaryViolationError`` when the call must not execute."""
        ...

    def validate(
        self,
        tool_name: str,
        message: ToolMessage,
        ledger: dict[str, Any],
    ) -> ToolMessage:
        """Validate (and optionally transform) a tool result before it
        becomes model-visible. Raise ``BoundaryViolationError`` to reject."""
        ...


def _ledger_from_state(state: Any) -> dict[str, Any]:
    if isinstance(state, Mapping):
        ledger = state.get("boundary_ledger")
    else:
        ledger = getattr(state, "boundary_ledger", None)
    return ledger if isinstance(ledger, dict) else {}


def _as_message_list(value: Any) -> list[AnyMessage]:
    if value is None:
        return []
    # BaseMessage, not AnyMessage: the latter is a subscripted alias and
    # cannot be used with isinstance.
    if isinstance(value, BaseMessage):
        return [value]
    return list(value)


def _is_call_result(message: AnyMessage, call_id: str) -> bool:
    return isinstance(message, ToolMessage) and message.tool_call_id == call_id


class BoundaryMiddleware(AgentMiddleware[BoundaryState, ContextT, ResponseT]):
    """Authorize every tool call before execution, validate every result
    after it, and persist policy bookkeeping in extended agent state."""

    state_schema = BoundaryState  # type: ignore[assignment]

    def __init__(
        self,
        policy: ToolBoundary,
        *,
        on_event: EventSink | None = None,
    ) -> None:
        super().__init__()
        self.policy = policy
        self.on_event = on_event or null_sink

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        context = self._call_context(request)
        try:
            self.policy.authorize(context.tool_name, context.arguments, context.ledger)
        except BoundaryViolationError as violation:
            self._emit_denial(context.tool_name, violation, "authorize")
            return violation.rejection.as_tool_message(context.call_id)
        result = handler(request)
        return self._validated_result(context, result)

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        context = self._call_context(request)
        try:
            self.policy.authorize(context.tool_name, context.arguments, context.ledger)
        except BoundaryViolationError as violation:
            self._emit_denial(context.tool_name, violation, "authorize")
            return violation.rejection.as_tool_message(context.call_id)
        result = await handler(request)
        return self._validated_result(context, result)

    # -- internals ---------------------------------------------------------

    def _call_context(self, request: ToolCallRequest) -> "_CallContext":
        tool_call = request.tool_call
        return _CallContext(
            tool_name=str(tool_call.get("name") or ""),
            call_id=str(tool_call.get("id") or ""),
            arguments=tool_call.get("args") or {},
            ledger=_ledger_from_state(request.state),
        )

    def _validated_result(
        self,
        context: "_CallContext",
        result: ToolMessage | Command[Any],
    ) -> ToolMessage | Command[Any]:
        if isinstance(result, Command):
            update = dict(result.update or {})
            messages = _as_message_list(update.get("messages"))
        else:
            update = {}
            messages = [result]

        try:
            validated = [
                self.policy.validate(context.tool_name, message, context.ledger)
                if _is_call_result(message, context.call_id)
                else message
                for message in messages
            ]
        except BoundaryViolationError as violation:
            self._emit_denial(context.tool_name, violation, "validate")
            validated = [
                violation.rejection.as_tool_message(context.call_id)
                if _is_call_result(message, context.call_id)
                else message
                for message in messages
            ]
        else:
            self.on_event(
                MiddlewareEvent(
                    "boundary_authorized",
                    tool_name=context.tool_name,
                    detail={"tool_call_id": context.call_id},
                )
            )

        update["messages"] = validated
        update["boundary_ledger"] = context.ledger
        return Command(update=update)

    def _emit_denial(
        self, tool_name: str, violation: BoundaryViolationError, phase: str
    ) -> None:
        rejection = violation.rejection
        self.on_event(
            MiddlewareEvent(
                "boundary_denied",
                tool_name=tool_name,
                detail={
                    "phase": phase,
                    "error_code": rejection.code,
                    "error_message": rejection.message,
                    "resource_refs": list(rejection.resource_refs),
                },
            )
        )


class _CallContext:
    __slots__ = ("tool_name", "call_id", "arguments", "ledger")

    def __init__(
        self,
        tool_name: str,
        call_id: str,
        arguments: Mapping[str, Any],
        ledger: dict[str, Any],
    ):
        self.tool_name = tool_name
        self.call_id = call_id
        self.arguments = arguments
        self.ledger = ledger


__all__ = [
    "BoundaryMiddleware",
    "BoundaryRejection",
    "BoundaryState",
    "BoundaryViolationError",
    "ToolBoundary",
]
