"""Shared native function-calling infrastructure for LLM investigation planners.

Both the evidence/analysis planner (:mod:`planner`) and the data-tool planner
(:mod:`data_tool_planner`) bind tools onto a chat model and parse native
``tool_calls``. This module holds the pieces they share so the two paths do not
duplicate tool packaging, call parsing, or message serialization.

Tool execution is intentionally not owned by the bound tools: a bound tool's
function raises so that the LangGraph execution node remains the only place a
tool can actually run. This keeps Policy and Audit in front of every call.
"""

from __future__ import annotations

from typing import Any, Iterable

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import StructuredTool
from pydantic import Field

from ...shared import StrictModel


class FinishInvestigationInput(StrictModel):
    objective: str = Field(min_length=10, description="结束调查并生成报告的中文原因")
    resolved_gap_ids: list[str] = Field(default_factory=list)
    unresolved_gap_ids: list[str] = Field(default_factory=list)


class RequestScopeExpansionInput(StrictModel):
    objective: str = Field(min_length=10, description="申请扩大调查范围的中文原因")
    requested_host_ids: list[str] = Field(min_length=1)
    reason_evidence_refs: list[str] = Field(min_length=1)
    reason_type: str = "related_host_evidence"
    requested_domains: list[str] = Field(default_factory=lambda: ["process", "file", "network"])
    start_time: Any | None = None
    end_time: Any | None = None


class DomainEvidenceQueryInput(StrictModel):
    """Fixed schema for the five domain evidence tools.

    ``gap_id`` selects the investigation question; the domain is encoded in the
    tool name (``query_<domain>_evidence``). The remaining fields are the query
    parameters the model is allowed to reason about freely.
    """

    gap_id: str = Field(min_length=1, description="要解决的证据缺口 ID（从当前可用缺口列表中选择）")
    host_id: str | None = Field(default=None, description="限定主机；缺省使用授权 Scope 内的主机")
    entity_ids: list[str] = Field(default_factory=list, description="按实体引用过滤")
    start_time: str | None = Field(default=None, description="ISO 时间下界；缺省使用授权时间窗口起点")
    end_time: str | None = Field(default=None, description="ISO 时间上界；缺省使用授权时间窗口终点")
    limit: int | None = Field(default=None, ge=1, le=5000, description="返回条数上限")


class AnalyzeEvidenceInput(StrictModel):
    """Trigger a deterministic analyzer over already collected evidence."""

    evidence_refs: list[str] = Field(min_length=1, description="要分析的历史证据 ID（从待处理分析义务列表中选择）")


class ActivateScenarioInput(StrictModel):
    """Activate a reviewed scenario template grounded in existing evidence."""

    scenario: str = Field(min_length=1, description="要激活的场景名（从 activatable_scenarios 中选择）")
    reason_refs: list[str] = Field(min_length=1, description="激活依据，必须是已存在的 Evidence / Fact / Finding ID")


def _not_directly_executable(**_kwargs: Any) -> None:
    raise RuntimeError("Tool execution is owned by JudgmentGraph")


def build_native_tools(specs: Iterable[tuple[str, type[StrictModel], str]]) -> list[StructuredTool]:
    """Wrap ``(name, args_schema, description)`` triples into bound tools.

    The wrapped function refuses to execute so that only the graph's execution
    node (which runs Policy and Audit) can actually invoke the tool.
    """

    return [
        StructuredTool.from_function(
            func=_not_directly_executable,
            name=name,
            description=description,
            args_schema=schema,
        )
        for name, schema, description in specs
    ]


def parse_tool_call(response: AIMessage) -> tuple[str, dict[str, Any], str]:
    """Return ``(name, args, call_id)`` for the first native tool call."""

    call = response.tool_calls[0]
    name = str(call["name"])
    arguments = dict(call.get("args") or {})
    call_id = str(call.get("id") or "")
    return name, arguments, call_id


def serialize_messages(messages: list[Any]) -> list[dict[str, Any]]:
    """Lossless-enough message serialization for observable model I/O events."""

    serialized: list[dict[str, Any]] = []
    for message in messages:
        item: dict[str, Any] = {"role": message.type, "content": message.content}
        if isinstance(message, AIMessage):
            item["tool_calls"] = message.tool_calls
        if isinstance(message, ToolMessage):
            item.update(
                {
                    "tool_call_id": message.tool_call_id,
                    "name": message.name,
                    "status": message.status,
                }
            )
        serialized.append(item)
    return serialized
