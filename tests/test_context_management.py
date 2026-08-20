from __future__ import annotations

import json

from langchain_core.messages import HumanMessage, SystemMessage

from threat_agent.bootstrap.settings import AppSettings
from threat_agent.case_management import initialize_state
from threat_agent.contracts import InvestigationToolLedger, InvestigationToolTrace
from threat_agent.judgment.application.data_tool_planner import StructuredDataToolPlanner
from threat_agent.shared.tokenizer import estimate_tokens


def _state():
    return initialize_state({
        "File_id": "file-a", "File_hash": "a" * 64, "File_path": "/tmp/a",
        "Sub_asset": "host-1", "tenant_id": "tenant-a", "run_id": "run-a",
    })


class _FakeModel:
    model_name = "fake-model"

    def bind_tools(self, tools, **_kwargs):
        self.bound_tools = tools
        return self


def _planner():
    return StructuredDataToolPlanner(
        _FakeModel(),
        context_window_tokens=100000,
        output_reserve_tokens=4096,
    )


def _trace(tool_name: str, returned_count: int) -> InvestigationToolTrace:
    return InvestigationToolTrace(
        sequence=1,
        tool_name=tool_name,
        arguments={},
        result_type="ActivityQueryResult",
        result={
            "execution_boundary": {"returned_count": returned_count},
            "activities": [
                {"activity_type": "process", "executable": "/tmp/sysupd", "pid": 1234}
            ] if returned_count else [],
        },
        tool_call_id=f"call-{tool_name}",
        model_message={},
    )


def test_tokenizer_weights_cjk_higher_than_ascii():
    ascii_tokens = estimate_tokens("a" * 100)
    cjk_tokens = estimate_tokens("中" * 100)
    assert cjk_tokens > ascii_tokens
    assert estimate_tokens("") >= 1


def test_settings_context_window_default_and_override():
    settings = AppSettings.load()
    assert settings.judgment_model.context_window_tokens == 100000
    assert settings.response_model.context_window_tokens == 100000
    assert settings.report_model.context_window_tokens == 100000
    # Per-role override wins over the common fallback.
    override = AppSettings.load(environ={
        "MODEL_CONTEXT_WINDOW_TOKENS": "100000",
        "JUDGMENT_MODEL_CONTEXT_WINDOW_TOKENS": "64000",
    })
    assert override.judgment_model.context_window_tokens == 64000
    assert override.response_model.context_window_tokens == 100000


def test_case_context_is_byte_stable_without_dynamic_fields():
    planner = _planner()
    state = _state()
    state.budget.iterations_used = 1
    first = planner._case_context(state)
    state.budget.iterations_used = 29
    second = planner._case_context(state)
    assert first == second
    serialized = json.dumps(first, ensure_ascii=False)
    assert "budget" not in serialized
    assert "iterations_used" not in serialized
    assert "round" not in serialized


def test_messages_layout_keeps_stable_prefix_and_trailing_dynamic():
    planner = _planner()
    state = _state()
    state.tool_ledger.traces.append(_trace("query_process_activities", 3))
    messages = planner._messages(state)
    assert isinstance(messages[0], SystemMessage)
    assert isinstance(messages[1], HumanMessage)
    # Stable prefix must not carry dynamic fields.
    assert "iterations_used" not in messages[1].content
    assert "budget" not in messages[1].content
    # Last message carries the progress projection.
    last = messages[-1]
    assert isinstance(last, HumanMessage)
    assert "queried_domains" in last.content
    assert "unqueried_domains" in last.content


def test_messages_expose_exactly_one_leading_system_message():
    # qwen/DashScope rejects any conversation with more than one system
    # message; everything injected mid-conversation must use another role.
    planner = _planner()
    state = _state()
    state.budget.iterations_used = 20  # past the reminder threshold
    for tool_name in (
        "query_process_activities",
        "query_network_activities",
        "query_file_activities",
    ):
        state.tool_ledger.traces.append(_trace(tool_name, 5))
    messages = planner._messages(state)
    system = [m for m in messages if isinstance(m, SystemMessage)]
    assert len(system) == 1
    assert messages[0] is system[0]


def test_compaction_summary_replays_as_human_message():
    planner = _planner()
    state = _state()
    planner._compaction_summary = "已查询进程与网络域，发现 C2 连接证据。"
    planner._replay_from = 1
    state.tool_ledger.traces.append(_trace("query_process_activities", 3))
    state.tool_ledger.traces.append(_trace("query_file_activities", 2))
    messages = planner._messages(state)
    system = [m for m in messages if isinstance(m, SystemMessage)]
    assert len(system) == 1
    summary = messages[2]
    assert isinstance(summary, HumanMessage)
    assert "C2 连接证据" in summary.content


def test_progress_projection_marks_unqueried_when_all_domains_queried():
    planner = _planner()
    state = _state()
    for tool_name in (
        "query_process_activities",
        "query_file_activities",
        "query_network_activities",
        "query_socket_activities",
        "query_service_activities",
        "query_package_activities",
        "query_asset_activities",
    ):
        state.tool_ledger.traces.append(_trace(tool_name, 1))
    progress = planner._build_progress(state)
    assert "process" in progress["queried_domains"]
    assert progress["unqueried_domains"] == []


def test_progress_projection_lists_unqueried_domains():
    planner = _planner()
    state = _state()
    state.tool_ledger.traces.append(_trace("query_process_activities", 1))
    progress = planner._build_progress(state)
    assert "file" in progress["unqueried_domains"]
    assert "network" in progress["unqueried_domains"]


def test_tool_history_truncation_keeps_call_result_pairs():
    planner = _planner()
    state = _state()
    for tool_name in (
        "query_process_activities",
        "query_network_activities",
        "query_file_activities",
    ):
        state.tool_ledger.traces.append(_trace(tool_name, 5))
    messages = planner._messages(state)
    # Count AIMessage/ToolMessage pairs between prefix and trailing dynamic.
    body = messages[2:-1]
    tool_calls = [m for m in body if m.type == "ai"]
    tool_results = [m for m in body if m.type == "tool"]
    assert len(tool_calls) == len(tool_results)


def test_tool_history_respects_token_budget():
    planner = StructuredDataToolPlanner(
        _FakeModel(), context_window_tokens=8192, output_reserve_tokens=4096
    )
    state = _state()
    # A huge result should still degrade through brief_result and fit the budget.
    for tool_name in ("query_process_activities", "query_file_activities"):
        state.tool_ledger.traces.append(_trace(tool_name, 5))
    messages = planner._messages(state)
    # The whole message list must stay well under the configured window.
    total = sum(estimate_tokens(m.content) for m in messages if m.content)
    assert total < 8192
