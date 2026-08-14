"""Lightweight per-round observation summary for the demo's event stream.

The data-tool gateway executes queries deterministically; the AI does not take
part in the queries themselves. This component lets the judgment model produce
a one-sentence Chinese observation describing *what one investigation round
actually found* — one LLM call per round, not per tool — so the demo's event
stream reflects the natural unit of observation (the round) instead of a bare
per-tool row count.

It is purely observational: failures are silently downgraded to ``None`` and
never affect the investigation flow.
"""

from __future__ import annotations

import json
from typing import Any

from ...shared.llm import invoke_llm

_SYSTEM_PROMPT = (
    "你是安全调查的观察记录助手。基于一轮调查中多次数据查询返回的结果，用一句简洁的中文"
    "描述这一轮调查实际查到了什么。只陈述事实（谁、对什么、做了什么），不推断恶意，"
    "不评价，不给出结论。不要罗列 ID。"
)

# Fields worth surfacing per activity type when briefing the model.
_ACTIVITY_FIELDS = (
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
        return {"returned_count": data.get("returned_count"), "timeline": brief}
    return data


class ToolObservationSummarizer:
    """Produce a one-sentence observation for a whole investigation round."""

    def __init__(self, model: Any):
        self.model = model

    def summarize_round(self, items: list[tuple[str, Any]]) -> str | None:
        """Summarize one round's tool results in a single LLM call.

        ``items`` is a list of ``(tool_name, result)`` for every tool executed
        in the round. Returns ``None`` on failure or when there is nothing to say.
        """
        briefs: list[dict[str, Any]] = []
        for tool_name, result in items:
            brief = brief_result(result)
            if brief is not None:
                briefs.append({"tool": tool_name, "result": brief})
        if not briefs:
            return None
        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps({"round": briefs}, ensure_ascii=False),
            },
        ]

        def invoke_once() -> str:
            response = self.model.invoke(messages)
            content = getattr(response, "content", "")
            if isinstance(content, list):
                content = "".join(str(part) for part in content)
            return str(content or "").strip()

        try:
            text = invoke_llm(
                invoke_once,
                parse_max_attempts=1,
                transport_max_attempts=2,
                transport_backoff=1.0,
            )
        except Exception:
            return None
        return text or None
