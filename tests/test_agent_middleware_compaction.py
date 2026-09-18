"""Component-level behavior tests for ReducerMiddleware (feature 15 step 04).

Gates from the implementation plan:

- tool results are downsized before entering history, with the original
  preserved in the message artifact;
- non-JSON content and reducer failures pass through unchanged;
- composing with the official SummarizationMiddleware keeps history bounded
  while every tool message in history stays reduced.
"""

from __future__ import annotations

import json

from langchain.agents import create_agent
from langchain.agents.middleware import SummarizationMiddleware
from langchain_core.language_models.fake_chat_models import (
    FakeListChatModel,
    GenericFakeChatModel,
)
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool

from threat_agent.agent_middleware import (
    ReducerMiddleware,
    UNREDUCED_ARTIFACT_KEY,
    MiddlewareEvent,
)


class _ScriptedModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


class _KeepOnlyCounts:
    """Reducer used only by these tests: keep ``returned_count`` only."""

    def reduce(self, tool_name: str, result):
        if isinstance(result, dict) and "activities" in result:
            return {"returned_count": len(result.get("activities", []))}
        return result


@tool
def query(host: str) -> dict:
    """Return a bulky activity query result."""
    activities = [
        {"activity_type": "process", "executable": f"/tmp/x{i}", "pid": 1000 + i,
         "command_line": "a" * 400, "host_ref": host}
        for i in range(12)
    ]
    return {"activities": activities, "execution_boundary": {"returned_count": 12}}


def _call(index: int, host: str = "h") -> dict:
    return {"name": "query", "args": {"host": host}, "id": f"call-{index}", "type": "tool_call"}


def test_tool_result_is_downsized_and_original_preserved_in_artifact():
    events: list[MiddlewareEvent] = []
    agent = create_agent(
        _ScriptedModel(messages=iter([
            AIMessage(content="", tool_calls=[_call(1)]),
            AIMessage(content="done"),
        ])),
        [query],
        middleware=[ReducerMiddleware(_KeepOnlyCounts(), on_event=events.append)],
    )
    result = agent.invoke({"messages": [HumanMessage("q")]})
    tool_message = next(
        m for m in result["messages"] if isinstance(m, ToolMessage)
    )
    assert json.loads(tool_message.content) == {"returned_count": 12}
    original = json.loads(tool_message.artifact[UNREDUCED_ARTIFACT_KEY])
    assert len(original["activities"]) == 12
    assert len(tool_message.content) < len(tool_message.artifact[UNREDUCED_ARTIFACT_KEY])
    assert [e.kind for e in events] == ["reducer_applied"]


def test_reducer_failure_passes_content_through():
    class _Broken:
        def reduce(self, tool_name, result):
            raise RuntimeError("boom")

    agent = create_agent(
        _ScriptedModel(messages=iter([
            AIMessage(content="", tool_calls=[_call(1)]),
            AIMessage(content="done"),
        ])),
        [query],
        middleware=[ReducerMiddleware(_Broken())],
    )
    result = agent.invoke({"messages": [HumanMessage("q")]})
    tool_message = next(
        m for m in result["messages"] if isinstance(m, ToolMessage)
    )
    assert len(json.loads(tool_message.content)["activities"]) == 12
    assert tool_message.artifact is None


def test_non_json_tool_content_is_left_alone():
    @tool
    def plain() -> str:
        """Return a plain string."""
        return "not json at all"

    agent = create_agent(
        _ScriptedModel(messages=iter([
            AIMessage(content="", tool_calls=[
                {"name": "plain", "args": {}, "id": "c1", "type": "tool_call"}
            ]),
            AIMessage(content="done"),
        ])),
        [plain],
        middleware=[ReducerMiddleware(_KeepOnlyCounts())],
    )
    result = agent.invoke({"messages": [HumanMessage("q")]})
    tool_message = next(
        m for m in result["messages"] if isinstance(m, ToolMessage)
    )
    assert tool_message.content == "not json at all"


def test_composition_with_official_summarization_keeps_history_bounded():
    # Main model drives three tool rounds then finishes; the summarization
    # model is a separate scripted instance dedicated to summary generation
    # (FakeListChatModel repeats its responses, which the official
    # middleware requires; a single-shot iterator exhausts and degrades).
    main = _ScriptedModel(messages=iter([
        AIMessage(content="", tool_calls=[_call(1)]),
        AIMessage(content="", tool_calls=[_call(2)]),
        AIMessage(content="", tool_calls=[_call(3)]),
        AIMessage(content="done"),
    ]))
    summarizer = FakeListChatModel(responses=["调查进展摘要：已查询三轮。"])
    events: list[MiddlewareEvent] = []
    agent = create_agent(
        main,
        [query],
        middleware=[
            SummarizationMiddleware(
                summarizer,
                trigger=("messages", 4),
                keep=("messages", 2),
            ),
            ReducerMiddleware(_KeepOnlyCounts(), on_event=events.append),
        ],
    )
    result = agent.invoke(
        {"messages": [HumanMessage("q")]}, config={"recursion_limit": 100}
    )
    messages = result["messages"]
    tool_messages = [m for m in messages if isinstance(m, ToolMessage)]
    # Every tool message that survived in history is the reduced form.
    assert tool_messages, "recent tool results must remain after summarization"
    for message in tool_messages:
        assert json.loads(message.content) == {"returned_count": 12}
    # The official middleware folded older history: the verbatim round count
    # in history is well below the three executed rounds.
    assert len(messages) < 3 * 2 + 2
    # Summarization actually happened: the injected summary rides in a human
    # message with the official prefix.
    summary_like = [
        m for m in messages
        if m.type == "human"
        and "Here is a summary" in str(m.content)
        and "调查进展摘要" in str(m.content)
    ]
    assert summary_like, f"no summary message found in {[m.type for m in messages]}"
