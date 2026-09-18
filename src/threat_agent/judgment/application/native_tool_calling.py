"""Shared native function-calling infrastructure for the LLM investigation planner.

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


def _not_directly_executable(**_kwargs: Any) -> None:
    raise RuntimeError("Legacy planner tools cannot execute directly")


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


def parse_tool_calls(response: AIMessage) -> list[tuple[str, dict[str, Any], str]]:
    """Return ``(name, args, call_id)`` for every native tool call in order."""

    result: list[tuple[str, dict[str, Any], str]] = []
    for call in response.tool_calls:
        name = str(call["name"])
        arguments = dict(call.get("args") or {})
        call_id = str(call.get("id") or "")
        result.append((name, arguments, call_id))
    return result


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
