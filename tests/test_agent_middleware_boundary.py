"""Component-level behavior tests for BoundaryMiddleware.

Runs against a real ``create_agent`` loop driven by a scripted fake model:
no business module, no LLM provider. Verifies the step-01 gates from the
feature 15 implementation plan:

- unauthorized calls produce a structured, stable rejection;
- a rejection never blocks the remaining tool calls of the same round;
- rejected content never becomes model-visible;
- the policy ledger survives across calls through extended agent state;
- boundary events are emitted for both denials and authorizations.
"""

from __future__ import annotations

import asyncio
import json

from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool

from threat_agent.agent_middleware import (
    BoundaryMiddleware,
    BoundaryRejection,
    BoundaryViolationError,
    MiddlewareEvent,
)

ALLOWED_HOST = "host-a"


class _ScriptedModel(GenericFakeChatModel):
    """Scripted model that accepts (and ignores) tool binding: the scripted
    responses already carry explicit tool_calls."""

    def bind_tools(self, tools, **kwargs):
        return self


class TablePolicy:
    """In-memory rule-table boundary used only by these tests.

    authorize: tools other than ``use_ref`` must target the allowed host;
    ``use_ref`` additionally requires the reference to be in the ledger.
    validate: records returned references into the ledger, rejects any
    result carrying a resource marked ``secret``.
    """

    def authorize(self, tool_name: str, arguments, ledger: dict) -> None:
        if tool_name != "use_ref" and arguments.get("host") != ALLOWED_HOST:
            raise BoundaryViolationError(BoundaryRejection(
                code="host_out_of_scope",
                tool_name=tool_name,
                message="请求主机超出唯一告警主机边界",
                resource_refs=[str(arguments.get("host"))],
            ))
        if tool_name == "use_ref":
            known = set(ledger.get("authorized_refs", []))
            if arguments.get("ref") not in known:
                raise BoundaryViolationError(BoundaryRejection(
                    code="reference_not_authorized",
                    tool_name=tool_name,
                    message="数据引用不属于本次运行已返回的活动",
                    resource_refs=[str(arguments.get("ref"))],
                ))

    def validate(self, tool_name: str, message: ToolMessage, ledger: dict) -> ToolMessage:
        try:
            payload = json.loads(message.content)
        except (TypeError, ValueError):
            return message
        resource_ref = payload.get("resource_ref")
        if isinstance(resource_ref, str):
            if resource_ref.startswith("secret"):
                raise BoundaryViolationError(BoundaryRejection(
                    code="reference_not_authorized",
                    tool_name=tool_name,
                    message="工具结果包含未授权引用",
                    resource_refs=[resource_ref],
                ))
            ledger.setdefault("authorized_refs", []).append(resource_ref)
        return message


@tool
def lookup(host: str) -> dict:
    """Return one activity reference for the requested host."""
    return {"host": host, "resource_ref": f"act-{host[-1]}"}


@tool
def lookup_secret(host: str) -> dict:
    """Return an activity reference that carries a secret resource."""
    return {"host": host, "resource_ref": f"secret-{host[-1]}"}


@tool
def use_ref(ref: str) -> dict:
    """Consume an activity reference previously returned in this run."""
    return {"consumed": ref}


def _agent(model, events: list[MiddlewareEvent], tools=None):
    return create_agent(
        model,
        tools if tools is not None else [lookup, use_ref],
        middleware=[BoundaryMiddleware(TablePolicy(), on_event=events.append)],
    )


def _tool_call(name: str, **arguments) -> dict:
    return {"name": name, "args": arguments, "id": f"call-{name}-{arguments}", "type": "tool_call"}


def _model(*responses: AIMessage) -> _ScriptedModel:
    return _ScriptedModel(messages=iter(list(responses)))


def _denial_payload(message: ToolMessage) -> dict:
    assert message.status == "error"
    return json.loads(message.content)


def test_unauthorized_call_returns_structured_rejection_and_loop_continues():
    model = _model(
        AIMessage(content="", tool_calls=[_tool_call("lookup", host="host-b")]),
        AIMessage(content="done"),
    )
    events: list[MiddlewareEvent] = []
    result = _agent(model, events).invoke({"messages": [HumanMessage("q")]})
    tool_messages = [m for m in result["messages"] if isinstance(m, ToolMessage)]
    assert len(tool_messages) == 1
    payload = _denial_payload(tool_messages[0])
    assert payload == {
        "error_type": "BoundaryDenied",
        "error_code": "host_out_of_scope",
        "error_message": "请求主机超出唯一告警主机边界",
        "resource_refs": ["host-b"],
    }
    # The loop continued past the denial: the model produced a final answer.
    assert result["messages"][-1].content == "done"


def test_rejection_error_code_is_stable_across_runs():
    def run_once() -> dict:
        model = _model(
            AIMessage(content="", tool_calls=[_tool_call("lookup", host="host-b")]),
            AIMessage(content="done"),
        )
        events: list[MiddlewareEvent] = []
        result = _agent(model, events).invoke({"messages": [HumanMessage("q")]})
        return _denial_payload([m for m in result["messages"] if isinstance(m, ToolMessage)][0])

    assert run_once() == run_once()


def test_rejection_does_not_block_same_round_calls():
    model = _model(
        AIMessage(content="", tool_calls=[
            _tool_call("lookup", host="host-a"),
            _tool_call("lookup", host="host-b"),
        ]),
        AIMessage(content="done"),
    )
    events: list[MiddlewareEvent] = []
    result = _agent(model, events).invoke({"messages": [HumanMessage("q")]})
    tool_messages = [m for m in result["messages"] if isinstance(m, ToolMessage)]
    assert len(tool_messages) == 2
    statuses = {m.tool_call_id: m.status for m in tool_messages}
    assert "call-lookup-{'host': 'host-a'}" in statuses
    assert statuses["call-lookup-{'host': 'host-a'}"] == "success"
    assert statuses["call-lookup-{'host': 'host-b'}"] == "error"


def test_rejected_content_never_becomes_model_visible():
    model = _model(
        AIMessage(content="", tool_calls=[_tool_call("lookup_secret", host="host-a")]),
        AIMessage(content="done"),
    )
    events: list[MiddlewareEvent] = []
    result = _agent(model, events, tools=[lookup_secret, use_ref]).invoke(
        {"messages": [HumanMessage("q")]}
    )
    serialized = json.dumps(
        [m.model_dump() for m in result["messages"]], ensure_ascii=False, default=str
    )
    assert "secret-host" not in serialized
    tool_messages = [m for m in result["messages"] if isinstance(m, ToolMessage)]
    assert _denial_payload(tool_messages[0])["error_code"] == "reference_not_authorized"


def test_ledger_persists_across_calls_via_state():
    model = _model(
        AIMessage(content="", tool_calls=[_tool_call("lookup", host="host-a")]),
        AIMessage(content="", tool_calls=[_tool_call("use_ref", ref="act-a")]),
        AIMessage(content="done"),
    )
    events: list[MiddlewareEvent] = []
    result = _agent(model, events).invoke({"messages": [HumanMessage("q")]})
    tool_messages = [m for m in result["messages"] if isinstance(m, ToolMessage)]
    assert len(tool_messages) == 2
    assert all(m.status == "success" for m in tool_messages)
    assert json.loads(tool_messages[1].content) == {"consumed": "act-a"}


def test_reference_unknown_to_ledger_is_denied():
    model = _model(
        AIMessage(content="", tool_calls=[_tool_call("use_ref", ref="act-z")]),
        AIMessage(content="done"),
    )
    events: list[MiddlewareEvent] = []
    result = _agent(model, events).invoke({"messages": [HumanMessage("q")]})
    tool_messages = [m for m in result["messages"] if isinstance(m, ToolMessage)]
    assert _denial_payload(tool_messages[0])["error_code"] == "reference_not_authorized"


def test_boundary_events_emitted_in_order():
    model = _model(
        AIMessage(content="", tool_calls=[
            _tool_call("lookup", host="host-a"),
            _tool_call("lookup", host="host-b"),
        ]),
        AIMessage(content="done"),
    )
    events: list[MiddlewareEvent] = []
    _agent(model, events).invoke({"messages": [HumanMessage("q")]})
    kinds = [(event.kind, event.detail.get("error_code")) for event in events]
    assert ("boundary_authorized", None) in kinds
    assert ("boundary_denied", "host_out_of_scope") in kinds
    denied = [e for e in events if e.kind == "boundary_denied"]
    assert denied[0].detail["phase"] == "authorize"
    assert denied[0].tool_name == "lookup"


def test_async_agent_path_enforces_boundary_too():
    model = _model(
        AIMessage(content="", tool_calls=[_tool_call("lookup", host="host-b")]),
        AIMessage(content="done"),
    )
    events: list[MiddlewareEvent] = []
    agent = _agent(model, events)
    result = asyncio.run(agent.ainvoke({"messages": [HumanMessage("q")]}))
    tool_messages = [m for m in result["messages"] if isinstance(m, ToolMessage)]
    assert _denial_payload(tool_messages[0])["error_code"] == "host_out_of_scope"
    assert any(event.kind == "boundary_denied" for event in events)
