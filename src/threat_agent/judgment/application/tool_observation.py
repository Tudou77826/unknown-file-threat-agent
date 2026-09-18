"""Deterministic tool-result downsizing for prompt context.

``brief_result`` keeps only the fields that carry investigation signal
(executable, command line, endpoints, relations, …) and drops raw large blobs
before tool history re-enters the model context. Round-level narrative is
emitted by the runtime's LLM bridge, not here.
"""

from __future__ import annotations

import json
from typing import Any

_SYSTEM_PROMPT = (
    "你是安全调查的观察记录助手。基于一轮调查中多次数据查询返回的结果，用一句简洁的中文"
    "描述这一轮调查实际查到了什么。只陈述事实（谁、对什么、做了什么），不推断恶意，"
    "不评价，不给出结论。不要罗列 ID。"
)

# Fields worth surfacing per activity type when briefing the model.
# ``activity_id`` is deliberately first: downstream tools (get_raw_records,
# calculate_activity_metrics) require the planner to quote activity IDs
# verbatim, so downsizing must never strip the identifiers it needs. Dropping
# them made the model invent IDs by pattern and get rejected every round.
_ACTIVITY_FIELDS = (
    "activity_id",
    "activity_type",
    "operation",
    "host_ref",
    "process_ref",
    "pid",
    "executable",
    "command_line",
    "parent_process_ref",
    "path",
    "protocol",
    "direction",
    "destination_endpoint_ref",
    "socket_ref",
    "file_ref",
    "service_ref",
    "package_ref",
    "repository",
    "signature_valid",
)


def _reference_ids(references: Any) -> list[str]:
    """Extract citable reference IDs from a query result's evidence list."""

    if not isinstance(references, list):
        return []
    ids: list[str] = []
    for reference in references:
        if isinstance(reference, dict):
            value = reference.get("evidence_id") or reference.get("id")
            if value:
                ids.append(str(value))
        elif reference:
            ids.append(str(reference))
    return ids


def brief_result(result: Any) -> Any:
    """Downsize a tool result to its salient fields for context embedding.

    This is the deterministic "summary degradation" used by the planner when
    replaying tool history: it keeps only the fields that carry investigation
    signal (executable, command line, endpoints, relations, …) and drops raw
    large blobs. Returns the original value unchanged when the shape is not a
    known query result.
    """
    data = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
    if not isinstance(data, dict):
        return data
    # Activity query result: surface only the salient fields per activity.
    activities = data.get("activities")
    if isinstance(activities, list):
        brief = []
        for activity in activities[:10]:
            if isinstance(activity, dict):
                brief.append(
                    {
                        key: activity[key]
                        for key in _ACTIVITY_FIELDS
                        if activity.get(key) is not None
                    }
                )
        boundary = data.get("execution_boundary") or {}
        return {
            "returned_count": boundary.get("returned_count"),
            # The authoritative list of refs this run may cite downstream.
            "evidence_references": _reference_ids(data.get("evidence_references")),
            "activities": brief,
        }
    # Entity exploration: timeline is the salient part.
    timeline = data.get("timeline")
    if isinstance(timeline, list):
        brief = []
        for activity in timeline[:10]:
            if isinstance(activity, dict):
                brief.append(
                    {
                        key: activity[key]
                        for key in _ACTIVITY_FIELDS
                        if activity.get(key) is not None
                    }
                )
        return {
            "returned_count": data.get("returned_count"),
            "evidence_references": _reference_ids(data.get("evidence_references")),
            "timeline": brief,
        }
    return data
