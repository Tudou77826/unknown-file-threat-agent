"""Behavior tests for ArchiveMiddleware (context archive design v4 §4.2).

Gates:

- interval rewrite legality: rounds are removed as AIMessage+ToolMessage
  pairs (no orphaned tool results), the case briefing prefix and the cards
  stay, one compact card replaces the span in place;
- guardrails: spans below the minimum rounds or token estimate are rejected
  deterministically with the current span echoed, and nothing is rewritten;
- idempotency: an already-archived span is never rewritten twice (parallel
  double-archive yields exactly one card);
- ID conservation: every citable ID of the span stays addressable — on the
  card and in the store's exact index;
- round markers: every model round is stamped ``[round N]`` with run-global
  numbering that survives archives, anchoring ``from_round``.
"""

from __future__ import annotations

import json

from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import StructuredTool

from threat_agent.agent_middleware import (
    ArchiveMiddleware,
    MiddlewareEvent,
)
from threat_agent.judgment.application.memory_store import MemoryStore


class _ScriptedModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


@StructuredTool.from_function
def query(host: str) -> dict:
    """Return an activity query result."""
    return {
        "query_id": "q-1",
        "activities": [
            {"activity_id": "act-1", "activity_type": "process",
             "command_line": "a" * 400, "host_ref": host}
        ],
        "evidence_references": [
            {"evidence_id": "ev-1", "activity_ref": "act-1", "query_id": "q-1"}
        ],
        "execution_boundary": {"returned_count": 1},
    }


@StructuredTool.from_function
def empty_query(host: str) -> dict:
    """Return a negative query result."""
    return {
        "query_id": "q-2",
        "activities": [],
        "evidence_references": [],
        "execution_boundary": {"returned_count": 0},
    }


def _call(index: int, name: str, args: dict) -> dict:
    return {"name": name, "args": args, "id": f"call-{index}", "type": "tool_call"}


def _agent(store, script, *, events=None, min_span_tokens: int = 50):
    middleware = ArchiveMiddleware(
        store,
        min_span_rounds=2,
        min_span_tokens=min_span_tokens,
        on_event=(events.append if events is not None else None),
    )
    return create_agent(
        _ScriptedModel(messages=iter(script)),
        [query, empty_query],
        middleware=[middleware],
    )


def _echo_payload(messages) -> dict:
    echoes = [
        json.loads(m.content)
        for m in messages
        if isinstance(m, ToolMessage) and m.name == "archive_context"
    ]
    assert echoes, "no archive_context echo in history"
    return echoes[0]


def test_interval_is_removed_in_pairs_and_replaced_by_one_card():
    store = MemoryStore()
    events: list[MiddlewareEvent] = []
    script = [
        AIMessage(content="查进程", tool_calls=[_call(1, "query", {"host": "h"})]),
        AIMessage(content="查外连", tool_calls=[_call(2, "empty_query", {"host": "h"})]),
        AIMessage(content="收束", tool_calls=[
            _call(3, "archive_context", {"summary": "进程查证完毕，未见异常外连" * 2})
        ]),
        AIMessage(content="done"),
    ]
    result = _agent(store, script, events=events).invoke(
        {"messages": [HumanMessage("case briefing")]}
    )
    messages = result["messages"]

    # No orphaned tool results: every ToolMessage's parent AIMessage survives.
    ai_call_ids = {
        str(call.get("id"))
        for m in messages if isinstance(m, AIMessage)
        for call in (m.tool_calls or [])
    }
    for m in messages:
        if isinstance(m, ToolMessage):
            assert m.tool_call_id in ai_call_ids, f"orphaned tool result {m.tool_call_id}"

    cards = [m for m in messages if m.additional_kwargs.get("lc_source") == "archive_card"]
    assert len(cards) == 1
    card_text = cards[0].content
    assert cards[0].additional_kwargs["archive_id"] == "arc-1"
    # The archived rounds' thinking and tool results are gone from context…
    assert not any("查进程" in str(m.content) or "查外连" in str(m.content) for m in messages)
    assert not any(
        isinstance(m, ToolMessage) and m.name in ("query", "empty_query")
        for m in messages
    )
    # …the briefing prefix and the current round stay, in that order.
    assert messages[0].content == "case briefing"
    assert cards[0] is messages[1]
    # Card carries the model summary plus the deterministic appendix facts.
    assert "进程查证完毕" in card_text
    assert "第 1–2 轮" in card_text
    assert "query(host=h)：返回 1" in card_text
    assert "empty_query(host=h)：返回 0（负结果）" in card_text
    assert "act-1" in card_text and "ev-1" in card_text

    echo = _echo_payload(messages)
    assert echo["archived"] is True
    assert echo["archive_id"] == "arc-1"
    assert echo["round_span"] == [1, 2]
    assert echo["model_rounds"] == 2
    assert echo["tool_calls"] == 2
    assert echo["produced_ids"] == {
        "activities": 1, "evidence": 1, "queries": 2,
    }
    assert any("返回 0 行" in item for item in echo["negative_results"])

    assert [e.kind for e in events] == [
        "archive_recorded", "archive_applied",
    ]
    assert store.handles() == ["arc-1"]
    assert store.stats()["rounds_archived"] == 2


def test_id_conservation_card_and_store_index_cover_every_citable_id():
    store = MemoryStore()
    script = [
        AIMessage(content="r1", tool_calls=[_call(1, "query", {"host": "h"})]),
        AIMessage(content="r2", tool_calls=[_call(2, "query", {"host": "h"})]),
        AIMessage(content="收束", tool_calls=[
            _call(3, "archive_context", {"summary": "两轮进程查证，证据充分可收束" * 2})
        ]),
        AIMessage(content="done"),
    ]
    result = _agent(store, script).invoke({"messages": [HumanMessage("briefing")]})
    card = next(
        m.content for m in result["messages"]
        if m.additional_kwargs.get("lc_source") == "archive_card"
    )
    for record_id in ("act-1", "ev-1", "q-1"):
        assert record_id in card, f"{record_id} missing from card"
        raw = store.get_raw(record_id)
        assert raw is not None and raw["archive_id"] == "arc-1"
    # The raw record is the original object carrying the ID, not a summary.
    assert store.get_raw("act-1")["raw"]["activity_id"] == "act-1"
    assert store.get_raw("act-1")["raw"]["command_line"] == "a" * 400
    # Snapshots preserve the original interval for recall expansion.
    block = store.get_archive("arc-1")
    assert [s["type"] for s in block["snapshots"]] == ["ai", "tool", "ai", "tool"]
    assert block["rounds"][0]["thinking"] == "r1"


def test_guardrail_rejects_short_span_without_touching_history():
    store = MemoryStore()
    events: list[MiddlewareEvent] = []
    script = [
        AIMessage(content="only round", tool_calls=[_call(1, "query", {"host": "h"})]),
        AIMessage(content="too early", tool_calls=[
            _call(2, "archive_context", {"summary": "过早归档尝试，应当被护栏拒绝" * 2})
        ]),
        AIMessage(content="done"),
    ]
    result = _agent(store, script, events=events).invoke(
        {"messages": [HumanMessage("briefing")]}
    )
    messages = result["messages"]
    echo = _echo_payload(messages)
    assert echo["archived"] is False
    assert echo["reason"] == "span_too_small"
    assert echo["current_span"]["rounds"] == 1
    assert echo["min_required"] == {"rounds": 2, "tokens": 50}
    # Nothing was rewritten: the round and its tool result are still there.
    assert any(isinstance(m, ToolMessage) and m.name == "query" for m in messages)
    assert not any(m.additional_kwargs.get("lc_source") == "archive_card" for m in messages)
    assert store.handles() == []
    assert events[0].kind == "archive_denied"
    assert events[0].detail["reason"] == "span_too_small"


def test_guardrail_rejects_span_below_token_estimate():
    store = MemoryStore()
    script = [
        AIMessage(content="r1", tool_calls=[_call(1, "query", {"host": "h"})]),
        AIMessage(content="r2", tool_calls=[_call(2, "query", {"host": "h"})]),
        AIMessage(content="收束", tool_calls=[
            _call(3, "archive_context", {"summary": "轮数够但token不够，应被拒绝" * 2})
        ]),
        AIMessage(content="done"),
    ]
    result = _agent(store, script, min_span_tokens=100_000).invoke(
        {"messages": [HumanMessage("briefing")]}
    )
    echo = _echo_payload(result["messages"])
    assert echo["archived"] is False
    assert echo["reason"] == "span_too_small"
    assert echo["current_span"]["rounds"] == 2
    assert 0 < echo["current_span"]["tokens"] < 100_000
    assert store.handles() == []


def test_parallel_double_archive_rewrites_once_idempotently():
    store = MemoryStore()
    summary = {"summary": "同轮并发归档，第二次必须幂等跳过" * 3}
    script = [
        AIMessage(content="r1", tool_calls=[_call(1, "query", {"host": "h"})]),
        AIMessage(content="r2", tool_calls=[_call(2, "query", {"host": "h"})]),
        AIMessage(content="double", tool_calls=[
            _call(3, "archive_context", dict(summary)),
            _call(4, "archive_context", dict(summary)),
        ]),
        AIMessage(content="done"),
    ]
    result = _agent(store, script).invoke({"messages": [HumanMessage("briefing")]})
    messages = result["messages"]
    cards = [m for m in messages if m.additional_kwargs.get("lc_source") == "archive_card"]
    assert len(cards) == 1, "double archive must not produce two cards"
    # The span was removed exactly once and no orphaned tool result remains.
    leftovers = [
        m for m in messages
        if isinstance(m, ToolMessage) and m.name in ("query", "empty_query")
    ]
    assert leftovers == []
    # Both echoes reached the model; at least one archive is addressable.
    echoes = [
        json.loads(m.content) for m in messages
        if isinstance(m, ToolMessage) and m.name == "archive_context"
    ]
    assert len(echoes) == 2
    assert all(e["archived"] for e in echoes)
    assert any(store.get_archive(e["archive_id"]) is not None for e in echoes)


def test_from_round_archives_only_the_tail_and_out_of_range_falls_back():
    store = MemoryStore()
    script = [
        AIMessage(content="r1", tool_calls=[_call(1, "query", {"host": "h"})]),
        AIMessage(content="r2", tool_calls=[_call(2, "query", {"host": "h"})]),
        AIMessage(content="r3", tool_calls=[_call(3, "query", {"host": "h"})]),
        AIMessage(content="r4", tool_calls=[_call(4, "query", {"host": "h"})]),
        AIMessage(content="partial", tool_calls=[
            _call(5, "archive_context",
                  {"summary": "只收旧方向：第 3 轮起的查证已闭环收束" * 2,
                   "from_round": 3})
        ]),
        AIMessage(content="done"),
    ]
    result = _agent(store, script).invoke({"messages": [HumanMessage("briefing")]})
    messages = result["messages"]
    echo = _echo_payload(messages)
    assert echo["archived"] is True
    assert echo["round_span"] == [3, 4]
    # Rounds 1–2 stay live before the card; 3–4 are gone.
    assert any("[round 1]" in str(m.content) and "\nr1" in str(m.content) for m in messages)
    assert any("[round 2]" in str(m.content) and "\nr2" in str(m.content) for m in messages)
    assert not any("r3" in str(m.content) or "r4" in str(m.content) for m in messages)
    card_index = next(
        i for i, m in enumerate(messages)
        if m.additional_kwargs.get("lc_source") == "archive_card"
    )
    assert any("[round 2]" in str(m.content) for m in messages[:card_index])
    assert not any("[round 2]" in str(m.content) for m in messages[card_index:])

    # Out-of-range anchor: default span + explicit adjustment echo.
    store2 = MemoryStore()
    script2 = [
        AIMessage(content="r1", tool_calls=[_call(1, "query", {"host": "h"})]),
        AIMessage(content="r2", tool_calls=[_call(2, "query", {"host": "h"})]),
        AIMessage(content="fallback", tool_calls=[
            _call(3, "archive_context",
                  {"summary": "from_round 越界应回退默认区间并回显说明" * 2,
                   "from_round": 99})
        ]),
        AIMessage(content="done"),
    ]
    result2 = _agent(store2, script2).invoke({"messages": [HumanMessage("briefing")]})
    echo2 = _echo_payload(result2["messages"])
    assert echo2["archived"] is True
    assert echo2["round_span"] == [1, 2]
    assert "from_round 未命中" in echo2["message"]


def test_round_markers_survive_archives_with_global_numbering():
    store = MemoryStore()
    script = [
        AIMessage(content="r1", tool_calls=[_call(1, "query", {"host": "h"})]),
        AIMessage(content="r2", tool_calls=[_call(2, "query", {"host": "h"})]),
        AIMessage(content="archive", tool_calls=[
            _call(3, "archive_context", {"summary": "前两轮已闭环，收束归档" * 3})
        ]),
        AIMessage(content="post", tool_calls=[_call(4, "query", {"host": "h"})]),
        AIMessage(content="done"),
    ]
    result = _agent(store, script).invoke({"messages": [HumanMessage("briefing")]})
    contents = [str(m.content) for m in result["messages"] if isinstance(m, AIMessage)]
    assert contents[0].startswith("[round 3]"), contents
    assert contents[1].startswith("[round 4]"), contents
    assert contents[2].startswith("[round 5]"), contents
    # Markers anchor from_round on the following archive.
    assert "[round 3]" in contents[0] and "[round 4]" in contents[1]


def test_defaults_match_the_design_thresholds():
    store = MemoryStore()
    middleware = ArchiveMiddleware(store)
    assert middleware.min_span_rounds == 2
    assert middleware.min_span_tokens == 1000
    assert [tool.name for tool in middleware.tools] == ["archive_context"]


def test_denied_tool_results_are_recorded_as_errors_in_the_block():
    from langchain_core.tools import StructuredTool

    @StructuredTool.from_function
    def denied_query(host: str) -> dict:
        """Return a structured boundary rejection payload."""
        return {
            "error_type": "BoundaryDenied",
            "error_code": "host_out_of_scope",
            "error_message": "请求主机超出唯一告警主机边界",
        }

    store = MemoryStore()
    script = [
        AIMessage(content="r1", tool_calls=[{
            "name": "denied_query", "args": {"host": "other"},
            "id": "call-1", "type": "tool_call",
        }]),
        AIMessage(content="r2", tool_calls=[_call(2, "query", {"host": "h"})]),
        AIMessage(content="收束", tool_calls=[
            _call(3, "archive_context", {"summary": "一次越界尝试被拒，一次正常查询" * 2})
        ]),
        AIMessage(content="done"),
    ]
    middleware = ArchiveMiddleware(store, min_span_rounds=2, min_span_tokens=1)
    agent = create_agent(_ScriptedModel(messages=iter(script)), [denied_query, query],
                         middleware=[middleware])
    result = agent.invoke({"messages": [HumanMessage("briefing")]})
    block = store.get_archive("arc-1")
    calls = [c for r in block["rounds"] for c in r["tool_calls"]]
    denied = next(c for c in calls if c["tool"] == "denied_query")
    assert denied["error"] and "BoundaryDenied" in str(denied["error"])
    assert denied["negative"] is True
    assert denied["returned"] is None
    card = next(
        m.content for m in result["messages"]
        if m.additional_kwargs.get("lc_source") == "archive_card"
    )
    assert "报错 BoundaryDenied" in card
    echo = _echo_payload(result["messages"])
    assert any("BoundaryDenied" in item for item in echo["negative_results"])
