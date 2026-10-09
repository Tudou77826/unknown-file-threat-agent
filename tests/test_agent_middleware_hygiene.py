"""History hygiene middleware tests (round-2 demo failure: one malformed
provider block crashed the next request's JSON formatting).

Gate from the incident: an AIMessage content block shaped like
``{"type": "server_tool_use", "input": {}, "partial_json": None}`` — the
artifact of a malformed tool call — made the next request formatting raise
``TypeError: the JSON object must be str, bytes or bytearray, not NoneType``
and killed the whole run. The middleware must fold or drop the artifact
before any model call and leave clean history untouched.
"""

from __future__ import annotations

import pytest
from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from threat_agent.agent_middleware import HistoryHygieneMiddleware


class _ScriptedModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def _dirty_ai_message() -> AIMessage:
    return AIMessage(
        content="",
        tool_calls=[{
            "name": "query", "args": {"host": "h"},
            "id": "call-1", "type": "tool_call",
        }],
        additional_kwargs={},
    )


def test_dirty_streaming_artifact_is_normalized():
    middleware = HistoryHygieneMiddleware()
    dirty = AIMessage(content=[
        {"type": "server_tool_use", "id": "t1", "name": "tool",
         "input": {}, "partial_json": None},
    ])
    state = {"messages": [HumanMessage("q"), dirty]}
    update = middleware.before_model(state, None)
    assert update is not None
    cleaned = update["messages"][-1]
    block = cleaned.content[0]
    assert "partial_json" not in block
    assert block["input"] == {}


def test_parseable_artifact_is_folded_into_input():
    middleware = HistoryHygieneMiddleware()
    dirty = AIMessage(content=[
        {"type": "server_tool_use", "id": "t1", "name": "tool",
         "input": {}, "partial_json": '{"host": "server-01"}'},
    ])
    update = middleware.before_model({"messages": [dirty]}, None)
    block = update["messages"][-1].content[0]
    assert block["input"] == {"host": "server-01"}


def test_clean_history_is_untouched():
    middleware = HistoryHygieneMiddleware()
    clean = AIMessage(content="plain thinking", tool_calls=[])
    assert middleware.before_model({"messages": [HumanMessage("q"), clean]}, None) is None
    blocky = AIMessage(content=[
        {"type": "text", "text": "hi"}, {"type": "tool_use", "id": "t", "name": "x", "input": {"a": 1}},
    ])
    assert middleware.before_model({"messages": [blocky]}, None) is None


def test_agent_survives_a_malformed_tool_call_round():
    # Round 1 executes a real tool; round 2 carries the provider's malformed
    # block in history; the loop must still reach its final answer.
    from langchain_core.tools import tool as tool_decorator

    @tool_decorator
    def query(host: str) -> dict:
        """Return a query result."""
        return {"activities": [{"activity_id": "act-1"}],
                "execution_boundary": {"returned_count": 1}}

    def call(index, name, args):
        return {"name": name, "args": args, "id": f"c{index}", "type": "tool_call"}

    # Round 2 carries the provider's malformed block alongside a real call.
    round2 = AIMessage(content="", tool_calls=[call(2, "query", {"host": "h"})])
    round2.content = [
        {"type": "text", "text": "r2"},
        {"type": "server_tool_use", "id": "bad", "name": "tool",
         "input": {}, "partial_json": None},
    ]
    agent = create_agent(
        _ScriptedModel(messages=iter([
            AIMessage(content="r1", tool_calls=[call(1, "query", {"host": "h"})]),
            round2,
            AIMessage(content="done"),
        ])),
        [query],
        middleware=[HistoryHygieneMiddleware()],
    )
    result = agent.invoke({"messages": [HumanMessage("briefing")]})
    assert result["messages"][-1].content == "done"
    # The malformed block never survives into the model-visible history.
    for message in result["messages"]:
        for block in (message.content if isinstance(message.content, list) else []):
            if isinstance(block, dict):
                assert "partial_json" not in block


def test_cleaned_history_formats_for_anthropic_without_crash():
    pytest.importorskip("langchain_anthropic")
    from langchain_anthropic.chat_models import _format_messages

    dirty = AIMessage(content=[
        {"type": "server_tool_use", "id": "t1", "name": "tool",
         "input": {}, "partial_json": None},
    ])
    # Before the fix this exact shape raises the incident's TypeError.
    with pytest.raises(TypeError):
        _format_messages([HumanMessage("hi"), dirty])
    middleware = HistoryHygieneMiddleware()
    update = middleware.before_model({"messages": [HumanMessage("hi"), dirty]}, None)
    cleaned = update["messages"][1:]
    system, formatted = _format_messages(cleaned)
    assert formatted is not None
