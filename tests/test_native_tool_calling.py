from __future__ import annotations

import json

import pytest
from langchain_core.messages import AIMessage, ToolMessage

from threat_agent.judgment.application.native_tool_calling import (
    FinishInvestigationInput,
    RequestScopeExpansionInput,
    build_native_tools,
    parse_tool_call,
    serialize_messages,
)


def test_build_native_tools_packages_schemas():
    tools = build_native_tools(
        [
            ("finish_investigation", FinishInvestigationInput, "结束调查并生成报告"),
            ("request_scope_expansion", RequestScopeExpansionInput, "申请扩大调查范围"),
        ]
    )
    by_name = {tool.name: tool for tool in tools}
    assert set(by_name) == {"finish_investigation", "request_scope_expansion"}
    finish_schema = by_name["finish_investigation"].args_schema.model_json_schema()
    assert "objective" in finish_schema["properties"]
    assert "resolved_gap_ids" in finish_schema["properties"]
    scope_schema = by_name["request_scope_expansion"].args_schema.model_json_schema()
    assert "requested_host_ids" in scope_schema["properties"]
    assert "reason_evidence_refs" in scope_schema["properties"]


def test_bound_tools_refuse_direct_execution():
    (tool,) = build_native_tools(
        [("finish_investigation", FinishInvestigationInput, "结束调查")]
    )
    with pytest.raises(RuntimeError, match="owned by JudgmentGraph"):
        tool.func(objective="结束调查并生成报告")


def test_parse_tool_call_returns_name_args_and_id():
    response = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "query_process_evidence",
                "args": {"gap_id": "gap-execution"},
                "id": "call-1",
                "type": "tool_call",
            }
        ],
    )
    name, args, call_id = parse_tool_call(response)
    assert name == "query_process_evidence"
    assert args == {"gap_id": "gap-execution"}
    assert call_id == "call-1"


def test_serialize_messages_is_json_serializable():
    messages = [
        AIMessage(content="", tool_calls=[{
            "name": "finish_investigation",
            "args": {"objective": "证据不足，结束调查"},
            "id": "call-1",
            "type": "tool_call",
        }]),
        ToolMessage(content='{"ok": true}', tool_call_id="call-1", name="finish_investigation"),
    ]
    serialized = serialize_messages(messages)
    assert serialized[0]["role"] == "ai"
    assert serialized[0]["tool_calls"][0]["name"] == "finish_investigation"
    assert serialized[1]["role"] == "tool"
    assert serialized[1]["tool_call_id"] == "call-1"
    json.dumps(serialized, ensure_ascii=False)
