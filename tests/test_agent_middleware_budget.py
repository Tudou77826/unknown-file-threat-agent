"""Component-level behavior tests for BudgetMiddleware.

Step-03 gates from the feature 15 implementation plan:

- tool-call budget exhaustion denies with a structured error result while
  the loop continues;
- model-call and token budget exhaustion raise the stop signal out of the
  agent invocation for the business degradation path;
- budget events are emitted for denials and the stop signal.
"""

from __future__ import annotations

import json

import pytest
from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool

from threat_agent.agent_middleware import (
    BudgetExhausted,
    BudgetMiddleware,
    LimitsBudgetPolicy,
    MiddlewareEvent,
)


class _ScriptedModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


@tool
def echo(value: str) -> dict:
    """Echo the value back."""
    return {"value": value}


def _call(index: int) -> dict:
    return {
        "name": "echo",
        "args": {"value": f"v{index}"},
        "id": f"call-{index}",
        "type": "tool_call",
    }


def test_tool_budget_denies_with_structured_error_and_loop_continues():
    events: list[MiddlewareEvent] = []
    agent = create_agent(
        _ScriptedModel(messages=iter([
            AIMessage(content="", tool_calls=[_call(1)]),
            AIMessage(content="", tool_calls=[_call(2)]),
            AIMessage(content="", tool_calls=[_call(3)]),
            AIMessage(content="", tool_calls=[_call(4)]),
            AIMessage(content="done"),
        ])),
        [echo],
        middleware=[BudgetMiddleware(max_tool_calls=2, on_event=events.append)],
    )
    result = agent.invoke({"messages": [HumanMessage("q")]})
    tool_messages = [m for m in result["messages"] if isinstance(m, ToolMessage)]
    assert [m.status for m in tool_messages] == ["success", "success", "error", "error"]
    denied = [json.loads(m.content) for m in tool_messages if m.status == "error"]
    assert all(payload["error_type"] == "BudgetDenied" for payload in denied)
    assert all(payload["error_dimension"] == "tool_calls" for payload in denied)
    # The loop continued to a final model answer.
    assert result["messages"][-1].content == "done"
    assert [e.kind for e in events].count("budget_denied") == 2


def test_model_call_budget_raises_stop_signal():
    events: list[MiddlewareEvent] = []
    agent = create_agent(
        _ScriptedModel(messages=iter([
            AIMessage(content="", tool_calls=[_call(1)]),
            AIMessage(content="", tool_calls=[_call(2)]),
        ])),
        [echo],
        middleware=[BudgetMiddleware(max_model_calls=1, on_event=events.append)],
    )
    with pytest.raises(BudgetExhausted) as exhausted:
        agent.invoke({"messages": [HumanMessage("q")]})
    assert exhausted.value.dimension == "model_calls"
    assert [e.kind for e in events] == ["budget_exhausted"]


def test_token_budget_raises_stop_signal():
    def _usage(total: int) -> dict:
        return {"input_tokens": total - 10, "output_tokens": 10, "total_tokens": total}

    events: list[MiddlewareEvent] = []
    agent = create_agent(
        _ScriptedModel(messages=iter([
            AIMessage(content="", tool_calls=[_call(1)], usage_metadata=_usage(60)),
            AIMessage(content="", tool_calls=[_call(2)], usage_metadata=_usage(60)),
            AIMessage(content="done", usage_metadata=_usage(60)),
        ])),
        [echo],
        middleware=[BudgetMiddleware(max_total_tokens=100, on_event=events.append)],
    )
    with pytest.raises(BudgetExhausted) as exhausted:
        agent.invoke({"messages": [HumanMessage("q")]})
    assert exhausted.value.dimension == "total_tokens"
    assert [e.kind for e in events] == ["budget_exhausted"]


def test_custom_policy_is_respected():
    class _OddCallsOnly:
        def allow_model_call(self, usage) -> None:
            return

        def allow_tool_call(self, usage) -> None:
            # Deny whenever an odd number of calls has already succeeded;
            # denied calls do not advance the counter.
            if usage.tool_calls % 2 == 1:
                raise BudgetExhausted("tool_calls", "奇数次成功调用后拒绝一次")

    events: list[MiddlewareEvent] = []
    agent = create_agent(
        _ScriptedModel(messages=iter([
            AIMessage(content="", tool_calls=[_call(1)]),
            AIMessage(content="", tool_calls=[_call(2)]),
            AIMessage(content="done"),
        ])),
        [echo],
        middleware=[BudgetMiddleware(_OddCallsOnly(), on_event=events.append)],
    )
    result = agent.invoke({"messages": [HumanMessage("q")]})
    statuses = [
        m.status for m in result["messages"] if isinstance(m, ToolMessage)
    ]
    assert statuses == ["success", "error"]


def test_limits_policy_shape_is_data_only():
    policy = LimitsBudgetPolicy(max_model_calls=5, max_tool_calls=10)
    assert policy.max_model_calls == 5
    assert policy.max_total_tokens is None
