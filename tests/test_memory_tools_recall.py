"""Behavior tests for the recall tool assembly (context archive design v4
§4.3, appendix A.2/A.3).

Gates:

- the three entries (question / archives / ids) are mutually exclusive and
  every entry validates its own bounds (archives <= 2, ids <= 3) with an
  explicit "batch it" rejection — never silent truncation;
- exact-address reads never fabricate: unknown handles answer with the
  available list, unknown IDs land in ``missing``;
- the question entry runs an independent-context probe agent over the store
  (open_archive / get_raw), returns a cited answer with usage counters and
  a token-accounted event;
- probe bounds hold: per-case call budget, per-probe open budget, step
  limit and answer token limit.
"""

from __future__ import annotations

import json

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from threat_agent.bootstrap.memory_tools import (
    RecallProbeBudget,
    build_recall_tools,
)
from threat_agent.bootstrap.settings import RecallSettings
from threat_agent.judgment.application.memory_store import MemoryStore


class _ScriptedProbe(GenericFakeChatModel):
    """Scripted probe model that accepts tool binding."""

    def bind_tools(self, tools, **kwargs):
        return self


class _LoopProbe(GenericFakeChatModel):
    """Probe model that keeps opening archives forever (step-limit test)."""

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        return ChatResult(
            generations=[
                ChatGeneration(
                    message=AIMessage(
                        content="",
                        tool_calls=[{
                            "name": "open_archive",
                            "args": {"handle": "arc-1"},
                            "id": "loop",
                            "type": "tool_call",
                        }],
                    )
                )
            ]
        )


def _seed_store() -> MemoryStore:
    store = MemoryStore()
    rounds = [
        {
            "round": 4,
            "thinking": "查证 /var/www 下的文件创建",
            "tool_calls": [{
                "tool": "query_file_activities",
                "args": {"path": "/var/www", "op": "create|write"},
                "args_digest": "op=create|write, path=/var/www",
                "returned": 3,
                "ids": {
                    "activities": ["act-12", "act-13", "act-14"],
                    "evidence": ["ev-12"],
                    "queries": ["q-4"],
                },
                "negative": False,
                "error": None,
            }],
        },
        {
            "round": 5,
            "thinking": "排除 p26 的可疑外连",
            "tool_calls": [{
                "tool": "query_network_activities",
                "args": {"process_ref": "p26"},
                "args_digest": "process_ref=p26",
                "returned": 0,
                "ids": {"queries": ["q-5"]},
                "negative": True,
                "error": None,
            }],
        },
    ]
    records = {
        "act-12": {"activity_id": "act-12", "path": "/var/www/a.sh", "operation": "create"},
        "act-13": {"activity_id": "act-13", "path": "/var/www/b.sh", "operation": "write"},
        "act-14": {"activity_id": "act-14", "path": "/var/www/c.sh", "operation": "write"},
        "ev-12": {"evidence_id": "ev-12", "activity_ref": "act-12"},
        "q-4": {"query_id": "q-4"},
        "q-5": {"query_id": "q-5"},
    }
    store.record_archive(
        summary="文件创建查证完毕，未见 p26 可疑外连",
        round_span=(4, 5),
        rounds=rounds,
        snapshots=[{"type": "ai", "content": "round 4"}],
        records=records,
    )
    return store


def _recall(store, *, settings=None, factory=None, budget=None, events=None):
    collected = events if events is not None else []
    sink = (lambda kind, message, details=None: collected.append((kind, details)))
    tools = build_recall_tools(
        store,
        probe_model_factory=factory,
        settings=settings or RecallSettings(),
        probe_budget=budget,
        emit=sink,
    )
    assert [tool.name for tool in tools] == ["recall"]
    return tools[0]


def _probe_factory(script):
    return lambda: _ScriptedProbe(messages=iter(script))


def _probe_script(answer: str, *opens: str):
    script = [
        AIMessage(content="", tool_calls=[{
            "name": "open_archive", "args": {"handle": handle},
            "id": f"probe-{index}", "type": "tool_call",
        }])
        for index, handle in enumerate(opens)
    ]
    script.append(AIMessage(content=answer))
    return script


# -- entry exclusivity and bounds -------------------------------------------


def test_three_entries_are_mutually_exclusive():
    recall = _recall(_seed_store())
    mixed = recall.invoke({"question": "外连去向？", "ids": ["act-12"]})
    assert mixed["error"] == "entry_points_exclusive"
    assert set(mixed["provided"]) == {"question", "ids"}
    triple = recall.invoke({
        "question": "q", "archives": ["arc-1"], "ids": ["act-12"],
    })
    assert triple["error"] == "entry_points_exclusive"
    none_given = recall.invoke({})
    assert none_given["error"] == "entry_points_exclusive"
    assert none_given["provided"] == []


def test_archives_entry_is_bounded_and_expands_full_detail():
    store = _seed_store()
    recall = _recall(store)
    over = recall.invoke({"archives": ["arc-1", "arc-1", "arc-1"]})
    assert over["error"] == "too_many_archives"
    assert "分批" in over["message"]

    result = recall.invoke({"archives": ["arc-1"]})
    assert result["truncated"] is False
    archive = result["archives"][0]
    assert archive["archive_id"] == "arc-1"
    assert archive["summary"] == "文件创建查证完毕，未见 p26 可疑外连"
    assert archive["round_span"] == [4, 5]
    first_round = archive["rounds"][0]
    assert first_round["thinking"] == "查证 /var/www 下的文件创建"
    call = first_round["tool_calls"][0]
    assert call["tool"] == "query_file_activities"
    assert call["returned"] == 3
    assert call["activity_ids"] == ["act-12", "act-13", "act-14"]
    assert call["evidence_ids"] == ["ev-12"]


def test_archives_entry_answers_unknown_handles_with_available_list():
    recall = _recall(_seed_store())
    result = recall.invoke({"archives": ["arc-9"]})
    assert result["archives"] == []
    assert result["available"] == ["arc-1"]
    assert "未找到所询归档" in result["message"]
    partial = recall.invoke({"archives": ["arc-9", "arc-1"]})
    assert len(partial["archives"]) == 1
    assert partial["missing"] == ["arc-9"]


def test_ids_entry_is_bounded_and_never_fabricates():
    recall = _recall(_seed_store())
    over = recall.invoke({"ids": ["a", "b", "c", "d"]})
    assert over["error"] == "too_many_ids"
    result = recall.invoke({"ids": ["act-12", "nope-1"]})
    assert result["truncated"] is False
    assert [record["record_id"] for record in result["records"]] == ["act-12"]
    assert result["records"][0]["raw"]["path"] == "/var/www/a.sh"
    assert result["missing"] == ["nope-1"]


# -- question entry: probe agent ---------------------------------------------


def test_probe_answers_with_citations_and_usage_counters():
    store = _seed_store()
    events: list[tuple] = []
    budget = RecallProbeBudget(max_calls=6)
    recall = _recall(
        store,
        factory=_probe_factory(_probe_script(
            "依据 arc-1：/var/www 下共 3 个文件创建（act-12、act-13、act-14），"
            "p26 无外连（负结果）",
            "arc-1",
        )),
        budget=budget,
        events=events,
    )
    result = recall.invoke({"question": "归档区里 /var/www 的文件创建结论是什么？"})
    assert "arc-1" in result["answer"]
    assert result["consulted"] == {"archives": ["arc-1"], "ids": []}
    assert result["probe_usage"] == {"opens": 1, "steps": 2}
    assert result["truncated"] is False
    probe_events = [event for event in events if event[0] == "recall"]
    assert probe_events, "probe token accounting event missing"
    detail = probe_events[-1][1]
    assert detail["entry"] == "question"
    assert detail["opens"] == 1 and detail["steps"] == 2
    assert budget.used == 1


def test_probe_budget_is_per_case_and_exhausts_explicitly():
    store = _seed_store()
    budget = RecallProbeBudget(max_calls=1)
    recall = _recall(store, factory=_probe_factory(_probe_script("答案", "arc-1")), budget=budget)
    first = recall.invoke({"question": "第一问"})
    assert "answer" in first
    second = recall.invoke({"question": "第二问"})
    assert second["error"] == "probe_budget_exhausted"
    assert "archives/ids" in second["message"]
    assert budget.used == 1, "exhausted calls must not consume further"


def test_probe_open_budget_bounds_expansions_within_one_probe():
    store = _seed_store()
    settings = RecallSettings(probe_max_opens=1)
    recall = _recall(
        store,
        settings=settings,
        factory=_probe_factory(
            _probe_script("基于 arc-1 的内容作答", "arc-1", "arc-1"),
        ),
    )
    result = recall.invoke({"question": "能展开几个归档？"})
    assert result["probe_usage"]["opens"] == 1
    assert result["consulted"]["archives"] == ["arc-1"]


def test_probe_step_limit_returns_explicit_guidance_instead_of_hanging():
    store = _seed_store()
    settings = RecallSettings(probe_max_steps=3)
    loop = _LoopProbe(messages=iter([]))  # _generate is overridden; iterator unused
    recall = _recall(store, settings=settings, factory=lambda: loop)
    result = recall.invoke({"question": "这个问题会被步数上限截断"})
    assert result["truncated"] is True
    assert "未能形成答案" in result["answer"]
    assert "recall(archives" in result["answer"]


def test_probe_answer_token_bound_truncates_with_explicit_marker():
    store = _seed_store()
    settings = RecallSettings(probe_answer_max_tokens=100)
    long_answer = "依据 arc-1：大量相关细节。" + "字段值与负结果。" * 80
    recall = _recall(
        store,
        settings=settings,
        factory=_probe_factory(_probe_script(long_answer)),
    )
    result = recall.invoke({"question": "带上全部细节"})
    assert result["truncated"] is True
    assert result["answer"].endswith("取原始记录））") or "已截断" in result["answer"]


def test_probe_without_factory_reports_it_explicitly():
    recall = _recall(_seed_store())
    result = recall.invoke({"question": "谁会回答？"})
    assert result["error"] == "probe_not_configured"
    assert "archives/ids" in result["message"]


def test_recall_tool_result_is_json_serializable_for_tool_messages():
    recall = _recall(_seed_store())
    for arguments in (
        {"archives": ["arc-1"]},
        {"ids": ["act-13"]},
        {"question": None, "archives": ["arc-1"], "ids": None},
    ):
        payload = recall.invoke(arguments)
        json.dumps(payload, ensure_ascii=False)
