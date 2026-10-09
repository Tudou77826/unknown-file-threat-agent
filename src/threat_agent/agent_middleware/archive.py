"""Model-driven interval archiving middleware.

``archive_context`` lets the model move a completed stretch of its own
history out of the conversation window: the interval's AIMessage/ToolMessage
rounds are removed pairwise (round boundaries make half-pairs structurally
impossible), one compact card — the model-written summary plus a
deterministically generated fact appendix — replaces them in place, and the
original interval is serialized into an injected archive store where it
stays addressable by handle (``arc-{k}``) and by every citable record ID it
produced.

Mechanics (design "上下文归档与召回" v4 §4.2):

- the archive tool call is intercepted in ``wrap_tool_call``: the span is
  resolved there, guard-checked, recorded into the store, and echoed back
  with the actual interval facts — the model immediately sees what was cut;
- the history rewrite itself happens in ``before_model`` before the next
  model call, via a pending directive threaded through middleware state
  (checkpointed with the graph, parallel-safe through list-appending
  reducers);
- every model round is stamped with a ``[round N]`` marker line at creation
  (``after_model``), giving ``from_round`` an objective anchor that survives
  archives (marker numbers are global to the run);
- already-archived intervals are never rewritten again (idempotency, the
  F12 freeze constraint), and spans below the minimum size (model rounds or
  estimated tokens) are rejected deterministically.

The middleware is domain-agnostic: what counts as a citable ID and how
results are counted is a small, overridable JSON-scan default; the store is
an injected protocol (see ``ArchiveStore``).
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, TypeVar

from langchain.agents.middleware.types import (
    AgentMiddleware,
    PrivateStateAttr,
    ToolCallRequest,
    add_messages,
)
from langchain_core.messages import (
    AIMessage,
    AnyMessage,
    HumanMessage,
    RemoveMessage,
    ToolMessage,
)
from langchain_core.tools import StructuredTool
from langgraph.graph.message import REMOVE_ALL_MESSAGES
from langgraph.types import Command
from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import Annotated, NotRequired, Required, TypedDict

from .compaction import UNREDUCED_ARTIFACT_KEY
from .events import EventSink, MiddlewareEvent, null_sink

ContextT = TypeVar("ContextT")
ResponseT = TypeVar("ResponseT")

ARCHIVE_CONTEXT_TOOL = "archive_context"

ARCHIVE_CONTEXT_DESCRIPTION = (
    "把一段已经完成使命的上下文移出对话窗口：区间内的思考与工具结果会被收起，"
    "原位只保留你写的摘要与一份事实附录，原内容存入归档区、随时可用 recall 取回。"
    "何时使用由你判断——一段内容的作用已经兑现（结论落定、方向排除、背景确认），"
    "后续大概率只需摘要而不需逐字细节时，就归档它。区间默认是自上一归档点以来的全部；"
    "查证不足两个模型轮时会被拒绝（归档无收益）。成功后会回显实际归档的区间与内容清单，"
    "与预期不符时用 recall 找回。"
)

_ROUND_MARKER = re.compile(r"^\[round (\d+)\]\s*")

# Tool-result JSON keys that carry citable record IDs, mapped to the
# appendix's ID groups. The default scanner is data-contract-shaped but
# domain-agnostic: it never interprets content, it only reads addresses.
_ID_KIND_KEYS = {
    "activity_id": "activities",
    "evidence_id": "evidence",
    "relation_id": "relations",
    "query_id": "queries",
}


class ArchiveToolInput(BaseModel):
    """``archive_context`` arguments — the model-visible contract."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(
        min_length=10,
        description=(
            "这段内容的摘要，写给未来看不到细节的你：这段做了什么、得到了什么"
            "（结论/排除/确认）、留下哪些关键线索。要自含依据"
        ),
    )
    from_round: int | None = Field(
        default=None,
        ge=1,
        description=(
            "归档区间默认自上一归档点起；需要只收走更早的某段时，用轮次标记指定起点"
        ),
    )


class ArchiveStore(Protocol):
    """Injection contract fulfilled by the run-scoped memory store."""

    def record_archive(
        self,
        *,
        summary: str,
        round_span: tuple[int, int] | list[int],
        rounds: list[dict[str, Any]],
        snapshots: list[dict[str, Any]],
        records: dict[str, Any],
    ) -> str:
        """Persist one interval block; return its handle (``arc-{k}``)."""
        ...


# -- deterministic helpers -------------------------------------------------


def _estimate_text_tokens(text: str) -> int:
    """Cheap stable token estimate: CJK-heavy text costs more per character.

    Mirrors the investigation system's shared estimator; duplicated here
    because the middleware package must stay importable standalone.
    """
    total = 0.0
    for char in text:
        code = ord(char)
        cjk = 0x3400 <= code <= 0x4DBF or 0x4E00 <= code <= 0x9FFF
        total += 0.6 if cjk else 0.25
    return int(total)


def _estimate_messages_tokens(messages: list[AnyMessage]) -> int:
    total = 0
    for message in messages:
        content = message.content
        if isinstance(content, str):
            total += _estimate_text_tokens(content)
        elif isinstance(content, list):
            for part in content:
                total += _estimate_text_tokens(part if isinstance(part, str) else str(part))
        for call in getattr(message, "tool_calls", None) or []:
            total += _estimate_text_tokens(
                json.dumps(call.get("args") or {}, ensure_ascii=False, default=str)
            )
    return total


def _marker_number(message: AIMessage) -> int | None:
    if isinstance(message.content, str):
        found = _ROUND_MARKER.match(message.content)
        if found:
            return int(found.group(1))
    return None


def _strip_marker(content: Any) -> str:
    text = content if isinstance(content, str) else json.dumps(
        content, ensure_ascii=False, default=str
    )
    return _ROUND_MARKER.sub("", text, count=1)


def _dedup(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def _collect_ids(payload: Any) -> tuple[dict[str, list[str]], dict[str, Any]]:
    """Scan one tool payload for citable IDs.

    Returns the IDs grouped by appendix kind and, for each ID, the immediate
    record object that carries it — the store's exact-address material for
    ``get_raw``.
    """
    ids: dict[str, list[str]] = {}
    records: dict[str, Any] = {}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                kind = _ID_KIND_KEYS.get(key)
                if kind is not None and isinstance(value, str) and value:
                    ids.setdefault(kind, []).append(value)
                    records.setdefault(value, node)
                elif key == "evidence_references" and isinstance(value, list):
                    # Downsized results carry plain ID strings here.
                    for item in value:
                        if isinstance(item, str) and item:
                            ids.setdefault("evidence", []).append(item)
                            records.setdefault(item, {"evidence_id": item})
                        else:
                            walk(item)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    if isinstance(payload, dict):
        walk(payload)
    return {kind: _dedup(values) for kind, values in ids.items()}, records


def _returned_count(payload: Any) -> int | None:
    if not isinstance(payload, dict):
        return None
    if isinstance(payload.get("returned_count"), int):
        return payload["returned_count"]
    boundary = payload.get("execution_boundary")
    if isinstance(boundary, dict) and isinstance(boundary.get("returned_count"), int):
        return boundary["returned_count"]
    for key in ("activities", "timeline", "records"):
        if isinstance(payload.get(key), list):
            return len(payload[key])
    return None


def _payload_of(message: ToolMessage | None) -> Any:
    """Original tool payload: the unreduced artifact if present, else content."""
    if message is None:
        return None
    artifact = message.artifact if isinstance(message.artifact, dict) else {}
    for source in (artifact.get(UNREDUCED_ARTIFACT_KEY), message.content):
        if isinstance(source, str) and source:
            try:
                parsed = json.loads(source)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                return parsed
    return None


def _args_digest(arguments: dict[str, Any]) -> str:
    parts = [
        f"{key}={str(value)[:40]}"
        for key, value in sorted(arguments.items())
    ]
    digest = ", ".join(parts)
    return digest[:120] + ("…" if len(digest) > 120 else "")


def _snapshot(message: AnyMessage) -> dict[str, Any]:
    """JSON-serializable full-fidelity snapshot of one archived message."""
    content = message.content
    snapshot: dict[str, Any] = {
        "type": message.type,
        "id": message.id,
        "content": content
        if isinstance(content, str)
        else json.dumps(content, ensure_ascii=False, default=str),
    }
    calls = getattr(message, "tool_calls", None) or []
    if calls:
        snapshot["tool_calls"] = [
            {"name": call.get("name"), "args": call.get("args") or {}, "id": call.get("id")}
            for call in calls
        ]
    if isinstance(message, ToolMessage):
        snapshot["tool_call_id"] = message.tool_call_id
        snapshot["name"] = message.name
        snapshot["status"] = message.status
        if isinstance(message.artifact, dict) and message.artifact:
            snapshot["artifact"] = _jsonable_dict(message.artifact)
    return snapshot


def _jsonable_dict(artifact: dict[str, Any]) -> dict[str, Any]:
    kept: dict[str, Any] = {}
    for key, value in artifact.items():
        try:
            json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError):
            continue
        kept[key] = value
    return kept


_ID_GROUP_ZH = {
    "activities": "活动",
    "evidence": "证据",
    "relations": "关系",
    "queries": "查询",
}


def _render_round_line(round_number: int, call: dict[str, Any]) -> str:
    head = f"- 第 {round_number} 轮 {call['tool']}({call['args_digest']})"
    if call.get("error"):
        return f"{head}：报错 {str(call['error'])[:80]}"
    line = f"{head}：返回 {call.get('returned')}"
    ids = call.get("ids") or {}
    id_values = [value for kind in ("activities", "evidence", "relations") for value in ids.get(kind, [])]
    if call.get("negative"):
        line += "（负结果）"
    if id_values:
        line += "，新 ID：" + "、".join(id_values[:12]) + (
            f" 等 {len(id_values)} 个" if len(id_values) > 12 else ""
        )
    return line


def _render_card(
    *,
    handle: str,
    summary: str,
    round_span: tuple[int, int],
    model_rounds: int,
    tool_calls: int,
    round_lines: list[str],
    ids_by_kind: dict[str, list[str]],
) -> str:
    lines = [
        f"[已归档 {handle}｜第 {round_span[0]}–{round_span[1]} 轮｜"
        f"{model_rounds} 个模型轮｜{tool_calls} 次工具调用]"
    ]
    lines.append(f"摘要：{summary}")
    lines.append("附录：")
    lines.extend(round_lines)
    id_parts = [
        f"{_ID_GROUP_ZH[kind]} {len(values)}（{'、'.join(values)}）"
        for kind in ("activities", "evidence", "relations", "queries")
        if (values := ids_by_kind.get(kind))
    ]
    if id_parts:
        lines.append("可引用 ID：" + "；".join(id_parts))
    lines.append(
        f"需要细节时用 recall 取回（question 提问／archives=[\"{handle}\"] 展开／ids=[…] 取原文）。"
    )
    return "\n".join(lines)


# -- middleware state --------------------------------------------------------


def _merge_ledger(
    current: dict[str, Any] | None, incoming: dict[str, Any] | None
) -> dict[str, Any]:
    """Union archived IDs and keep the max archived-round counter — parallel
    archive calls each carry the same base ledger, so this is parallel-safe."""
    base = dict(current or {})
    other = incoming or {}
    ids = set(base.get("archived_message_ids") or []) | set(
        other.get("archived_message_ids") or []
    )
    base["archived_message_ids"] = sorted(ids)
    base["rounds_archived"] = max(
        base.get("rounds_archived", 0), other.get("rounds_archived", 0)
    )
    return base


def _append_pending(
    current: list[dict[str, Any]] | None, incoming: list[dict[str, Any]] | None
) -> list[dict[str, Any]]:
    # An empty incoming list is the rewrite hook's "all processed" signal;
    # anything else appends (parallel archive calls accumulate directives).
    if not incoming:
        return []
    return list(current or []) + list(incoming)


class ArchiveState(TypedDict, total=False):
    messages: Required[Annotated[list[AnyMessage], add_messages]]
    archive_ledger: NotRequired[
        Annotated[dict[str, Any], PrivateStateAttr, _merge_ledger]
    ]
    archive_pending: NotRequired[
        Annotated[list[dict[str, Any]], PrivateStateAttr, _append_pending]
    ]


def _state_value(state: Any, key: str) -> Any:
    if isinstance(state, dict):
        return state.get(key)
    return getattr(state, key, None)


def _rounds_of(messages: list[AnyMessage]) -> list[dict[str, Any]]:
    """Group the live message list into model rounds.

    One model round = one AIMessage plus its paired ToolMessages. Messages
    before the first AIMessage (case briefing, earlier cards) belong to no
    round and are never archived.
    """
    rounds: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for message in messages:
        if isinstance(message, AIMessage):
            current = {"ai": message, "tools": []}
            rounds.append(current)
        elif isinstance(message, ToolMessage) and current is not None:
            current["tools"].append(message)
    return rounds


class ArchiveMiddleware(AgentMiddleware[ArchiveState, ContextT, ResponseT]):
    """Archive message intervals into an external store, leave cards behind."""

    state_schema = ArchiveState  # type: ignore[assignment]

    def __init__(
        self,
        store: ArchiveStore,
        *,
        min_span_rounds: int = 2,
        min_span_tokens: int = 1000,
        on_event: EventSink | None = None,
    ) -> None:
        super().__init__()
        self.store = store
        self.min_span_rounds = min_span_rounds
        self.min_span_tokens = min_span_tokens
        self.on_event = on_event or null_sink

        def unreachable(**_arguments: Any) -> dict[str, Any]:
            # Always intercepted in wrap_tool_call; executing the bare tool
            # means the middleware stack was assembled without this instance.
            return {
                "error": "archive_middleware_not_installed",
                "message": "archive_context 必须经由 ArchiveMiddleware 执行",
            }

        self.tools = [
            StructuredTool.from_function(
                func=unreachable,
                name=ARCHIVE_CONTEXT_TOOL,
                description=ARCHIVE_CONTEXT_DESCRIPTION,
                args_schema=ArchiveToolInput,
            )
        ]

    # -- tool interception ---------------------------------------------------

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        if str(request.tool_call.get("name") or "") != ARCHIVE_CONTEXT_TOOL:
            return handler(request)
        return self._archive(request)

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        if str(request.tool_call.get("name") or "") != ARCHIVE_CONTEXT_TOOL:
            return await handler(request)
        return self._archive(request)

    # -- history rewrite -----------------------------------------------------

    def before_model(self, state, runtime) -> dict[str, Any] | None:
        pending = _state_value(state, "archive_pending") or []
        if not pending:
            return None
        messages = list(state["messages"])
        ledger = dict(_state_value(state, "archive_ledger") or {})
        rebuilt = messages
        applied: list[tuple[dict[str, Any], int]] = []
        for directive in pending:
            rebuilt, removed = self._apply_directive(rebuilt, directive)
            if removed:
                applied.append((directive, removed))
        ledger["rounds_archived"] = ledger.get("rounds_archived", 0) + sum(
            directive["rounds"] for directive, removed in applied
        )
        for directive, removed in applied:
            self.on_event(
                MiddlewareEvent(
                    "archive_applied",
                    tool_name=ARCHIVE_CONTEXT_TOOL,
                    detail={
                        "archive_id": directive["handle"],
                        "round_span": list(directive["round_span"]),
                        "removed_messages": removed,
                    },
                )
            )
        return {
            "messages": [RemoveMessage(id=REMOVE_ALL_MESSAGES), *rebuilt],
            "archive_pending": [],
            "archive_ledger": ledger,
        }

    async def abefore_model(self, state, runtime) -> dict[str, Any] | None:
        return self.before_model(state, runtime)

    # -- round markers ---------------------------------------------------------

    def after_model(self, state, runtime) -> dict[str, Any] | None:
        messages = state["messages"]
        last = messages[-1] if messages else None
        if not isinstance(last, AIMessage) or last.additional_kwargs.get(
            "archive_round_marked"
        ):
            return None
        content = last.content
        if not isinstance(content, str):
            return None
        ledger = _state_value(state, "archive_ledger") or {}
        rounds_archived = int(ledger.get("rounds_archived", 0) or 0)
        live_rounds = sum(1 for message in messages if isinstance(message, AIMessage))
        number = rounds_archived + live_rounds
        marked = last.model_copy(
            update={
                "content": f"[round {number}]" + (f"\n{content}" if content else ""),
                "additional_kwargs": {
                    **last.additional_kwargs, "archive_round_marked": number
                },
            }
        )
        return {"messages": [marked]}

    async def aafter_model(self, state, runtime) -> dict[str, Any] | None:
        return self.after_model(state, runtime)

    # -- internals --------------------------------------------------------------

    def _archive(self, request: ToolCallRequest) -> ToolMessage | Command[Any]:
        tool_call = request.tool_call
        call_id = str(tool_call.get("id") or "")
        arguments = dict(tool_call.get("args") or {})
        summary = str(arguments.get("summary") or "")
        from_round = arguments.get("from_round")
        messages = list(_state_value(request.state, "messages") or [])
        ledger = dict(_state_value(request.state, "archive_ledger") or {})

        def echo(payload: dict[str, Any], *, error: bool = False) -> Command[Any]:
            message = ToolMessage(
                content=json.dumps(payload, ensure_ascii=False),
                tool_call_id=call_id,
                name=ARCHIVE_CONTEXT_TOOL,
                status="error" if error else "success",
            )
            return Command(update={"messages": [message]})

        rounds = _rounds_of(messages)
        current_index = next(
            (
                index
                for index, round_ in enumerate(rounds)
                if any(
                    str(call.get("id") or "") == call_id
                    for call in (round_["ai"].tool_calls or [])
                )
            ),
            len(rounds) - 1,
        )
        if current_index < 0:
            return echo(self._rejection(rounds=0, tokens=0), error=True)
        completed = rounds[:current_index]
        numbers = self._round_numbers(rounds, ledger)

        start_index = 0
        adjusted = False
        if from_round is not None:
            try:
                wanted = int(from_round)
            except (TypeError, ValueError):
                wanted = None
            if wanted is None or wanted not in numbers[:current_index]:
                # Out-of-range anchors fall back to the default span and the
                # echo shows the span actually used.
                adjusted = True
            else:
                start_index = numbers[:current_index].index(wanted)
        span_rounds = completed[start_index:]
        span_messages = [
            message
            for round_ in span_rounds
            for message in (round_["ai"], *round_["tools"])
        ]
        span_tokens = _estimate_messages_tokens(span_messages)

        if len(span_rounds) < self.min_span_rounds or span_tokens < self.min_span_tokens:
            self.on_event(
                MiddlewareEvent(
                    "archive_denied",
                    tool_name=ARCHIVE_CONTEXT_TOOL,
                    detail={
                        "reason": "span_too_small",
                        "tool_call_id": call_id,
                        "rounds": len(span_rounds),
                        "tokens": span_tokens,
                    },
                )
            )
            rejection = self._rejection(rounds=len(span_rounds), tokens=span_tokens)
            return echo(rejection, error=True)

        archived_ids = set(ledger.get("archived_message_ids") or [])
        if any(message.id is not None and message.id in archived_ids for message in span_messages):
            self.on_event(
                MiddlewareEvent(
                    "archive_denied",
                    tool_name=ARCHIVE_CONTEXT_TOOL,
                    detail={
                        "reason": "span_already_archived",
                        "tool_call_id": call_id,
                    },
                )
            )
            return echo(
                {
                    "archived": False,
                    "reason": "span_already_archived",
                    "message": "所请求区间已归档过，不会再改写；需要细节用 recall 取回",
                },
                error=True,
            )

        rounds_facts, ids_by_kind, records, tool_call_count, negatives = (
            self._interval_facts(span_rounds, numbers[start_index : current_index])
        )
        span_numbers = numbers[start_index : current_index]
        round_span = (
            span_numbers[0],
            span_numbers[-1],
        )
        handle = self.store.record_archive(
            summary=summary,
            round_span=round_span,
            rounds=rounds_facts,
            snapshots=[_snapshot(message) for message in span_messages],
            records=records,
        )
        round_lines = [
            _render_round_line(fact["round"], call)
            for fact in rounds_facts
            for call in fact["tool_calls"]
        ]
        card = _render_card(
            handle=handle,
            summary=summary,
            round_span=round_span,
            model_rounds=len(span_rounds),
            tool_calls=tool_call_count,
            round_lines=round_lines,
            ids_by_kind=ids_by_kind,
        )
        produced = {kind: len(values) for kind, values in ids_by_kind.items()}
        activity_count = produced.get("activities", 0)
        message_text = (
            f"已归档 {handle}：第 {round_span[0]}–{round_span[1]} 轮、"
            f"{tool_call_count} 次工具调用、{activity_count} 个活动 ID，recall 可展开"
        )
        if adjusted:
            message_text += "；from_round 未命中，已按默认区间处理"
        self.on_event(
            MiddlewareEvent(
                "archive_recorded",
                tool_name=ARCHIVE_CONTEXT_TOOL,
                detail={
                    "archive_id": handle,
                    "tool_call_id": call_id,
                    "round_span": list(round_span),
                    "model_rounds": len(span_rounds),
                    "tool_calls": tool_call_count,
                    "produced_ids": produced,
                    "estimated_tokens": span_tokens,
                },
            )
        )
        directive = {
            "handle": handle,
            "message_ids": [
                message.id for message in span_messages if message.id is not None
            ],
            "rounds": len(span_rounds),
            "round_span": list(round_span),
            "card": card,
        }
        ledger["archived_message_ids"] = sorted(
            archived_ids | {m.id for m in span_messages if m.id is not None}
        )
        payload = {
            "archived": True,
            "archive_id": handle,
            "round_span": list(round_span),
            "model_rounds": len(span_rounds),
            "tool_calls": tool_call_count,
            "produced_ids": produced,
            "negative_results": negatives,
            "message": message_text,
        }
        return Command(
            update={
                "messages": [
                    ToolMessage(
                        content=json.dumps(payload, ensure_ascii=False),
                        tool_call_id=call_id,
                        name=ARCHIVE_CONTEXT_TOOL,
                    )
                ],
                "archive_pending": [directive],
                "archive_ledger": ledger,
            }
        )

    def _rejection(self, *, rounds: int, tokens: int) -> dict[str, Any]:
        return {
            "archived": False,
            "reason": "span_too_small",
            "current_span": {"rounds": rounds, "tokens": tokens},
            "min_required": {"rounds": self.min_span_rounds, "tokens": self.min_span_tokens},
            "message": "区间过短，归档无收益；继续工作，待这段内容完成使命后再归档",
        }

    def _round_numbers(
        self, rounds: list[dict[str, Any]], ledger: dict[str, Any]
    ) -> list[int]:
        """Global round numbers: markers are authoritative, position plus the
        archived-round offset is the fallback for unmarked messages."""
        offset = int(ledger.get("rounds_archived", 0) or 0)
        numbers: list[int] = []
        for index, round_ in enumerate(rounds):
            marked = _marker_number(round_["ai"])
            numbers.append(marked if marked is not None else offset + index + 1)
        return numbers

    def _interval_facts(
        self, span_rounds: list[dict[str, Any]], span_numbers: list[int]
    ) -> tuple[list[dict[str, Any]], dict[str, list[str]], dict[str, Any], int, list[str]]:
        rounds_facts: list[dict[str, Any]] = []
        ids_by_kind: dict[str, list[str]] = {}
        records: dict[str, Any] = {}
        negatives: list[str] = []
        tool_call_count = 0
        for round_, number in zip(span_rounds, span_numbers):
            calls: list[dict[str, Any]] = []
            for call in round_["ai"].tool_calls or []:
                tool_name = str(call.get("name") or "")
                arguments = dict(call.get("args") or {})
                digest = _args_digest(arguments)
                paired = next(
                    (
                        tool
                        for tool in round_["tools"]
                        if tool.tool_call_id == str(call.get("id") or "")
                    ),
                    None,
                )
                payload = _payload_of(paired)
                ids, call_records = _collect_ids(payload)
                returned = _returned_count(payload)
                error = (
                    payload.get("error") if isinstance(payload, dict) else None
                )
                if error is None and isinstance(payload, dict) and payload.get("error_type"):
                    # Structured rejections (boundary / budget / input errors)
                    # carry their shape under error_type, not error.
                    error = "{}: {}".format(
                        payload.get("error_type"),
                        str(payload.get("error_message") or payload.get("message") or "")[:80],
                    )
                negative = returned == 0 or error is not None
                if negative:
                    negatives.append(
                        f"{tool_name}({digest}) "
                        + (f"返回 0 行" if returned == 0 else f"报错 {str(error)[:60]}")
                    )
                for kind, values in ids.items():
                    ids_by_kind.setdefault(kind, [])
                    for value in values:
                        if value not in ids_by_kind[kind]:
                            ids_by_kind[kind].append(value)
                for record_id, record in call_records.items():
                    records.setdefault(record_id, record)
                calls.append(
                    {
                        "tool": tool_name,
                        "tool_call_id": str(call.get("id") or "") or None,
                        "args": arguments,
                        "args_digest": digest,
                        "returned": returned,
                        "ids": ids,
                        "negative": negative,
                        "error": error,
                    }
                )
                tool_call_count += 1
            rounds_facts.append(
                {
                    "round": number,
                    "thinking": _strip_marker(round_["ai"].content),
                    "tool_calls": calls,
                }
            )
        return rounds_facts, ids_by_kind, records, tool_call_count, negatives

    def _apply_directive(
        self, messages: list[AnyMessage], directive: dict[str, Any]
    ) -> tuple[list[AnyMessage], int]:
        """Remove one directive's span messages, insert its card in place.

        The card lands after the last removed message so multiple cards stay
        in creation order; messages between removed rounds (earlier cards,
        the case briefing) are never touched.
        """
        span_ids = set(directive["message_ids"])
        kept: list[AnyMessage] = []
        last_removed_index: int | None = None
        for index, message in enumerate(messages):
            if message.id is not None and message.id in span_ids:
                last_removed_index = index
                continue
            kept.append(message)
        if last_removed_index is None:
            # Already rewritten (idempotent re-entry): nothing to do.
            return messages, 0
        insert_at = sum(
            1
            for index, message in enumerate(messages)
            if index < last_removed_index
            and not (message.id is not None and message.id in span_ids)
        )
        card = HumanMessage(
            content=directive["card"],
            additional_kwargs={"lc_source": "archive_card", "archive_id": directive["handle"]},
        )
        rebuilt = kept[:insert_at] + [card] + kept[insert_at:]
        return rebuilt, len(span_ids)


__all__ = [
    "ARCHIVE_CONTEXT_TOOL",
    "ARCHIVE_CONTEXT_DESCRIPTION",
    "ArchiveMiddleware",
    "ArchiveState",
    "ArchiveStore",
    "ArchiveToolInput",
]
