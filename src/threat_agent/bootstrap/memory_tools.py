"""Recall tool assembly over the run-scoped archive memory (design v4 §4.3).

Three mutually exclusive entries:

- ``question`` — an independent-context probe agent answers questions over
  the archive region. Built on ``create_agent`` with two read-only tools
  (``open_archive`` / ``get_raw``); its process and the originals it opens
  never enter the main context, only the cited answer comes back. Bounded
  per probe (opens / steps / answer tokens) and per case (probe calls);
- ``archives`` — exact-handle expansion of whole archive blocks back into
  the main context ("want the original, not an answer");
- ``ids`` — exact-address fetch of original records, with an explicit
  ``missing`` list (never fabricated).

The probe answers generously — a question means the archived detail is
actually needed — but is second-hand by contract: the system prompt and the
recall tool description both state that critical facts must be confirmed
against records fetched by ID.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from langchain.agents import create_agent
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import StructuredTool
from langgraph.errors import GraphRecursionError
from pydantic import Field

from ..judgment.application.memory_store import MemoryStore
from ..shared import StrictModel
from ..shared.tokenizer import estimate_tokens
from .settings import AppSettings, RecallSettings, build_chat_model

RECALL_TOOL = "recall"

RECALL_DESCRIPTION = (
    "查看被归档的内容，三种方式任选其一：①提问题（question）——一个独立上下文的探查助手"
    "会在归档区里查找并回答，答案注明依据的归档与记录 ID；②按句柄展开（archives）——"
    "整段细节回到你的上下文，你亲自重看；③按 ID 取原文（ids）——取某条证据的完整字段。"
    "注意：探查答案是二手提炼，下结论的关键事实请以按 ID 取回的原始记录为准。"
)

PROBE_SYSTEM_PROMPT = (
    "你是安全调查归档区的探查助手，在独立上下文里回答主调查者的问题。\n"
    "可用材料：用户消息里的归档卡索引（句柄、摘要、轮次范围、ID 清单），"
    "以及两个只读工具：open_archive(handle) 展开某个归档的完整内容，"
    "get_raw(record_id) 取某条记录的原始字段。\n"
    "工作方式：自行决定看什么、看多深，直到能回答；找不到就明确说找不到，绝不编造。\n"
    "答案契约：\n"
    "- 必须注明所依据的归档句柄（如 arc-2）与记录 ID；\n"
    "- 慷慨携带相关细节：与问题相关的字段值、时间、ID、伴随的负结果一并带回，"
    "不只给最小答案，也不展开无关内容；\n"
    "- 只回答所问的问题，不复述无关内容；\n"
    "- 只查证事实，不做威胁判断——判断留给主调查者；\n"
    "- 你的答案是二手提炼，需下结论的关键事实请提醒主调查者用 recall(ids=[…]) 取原始记录核对。"
)

_PROBE_TRUNCATION_NOTE = (
    "……（答案超出探查上限已截断；关键事实请用 recall(ids=[…]) 取原始记录）"
)


class RecallInput(StrictModel):
    """``recall`` arguments — three mutually exclusive entries."""

    question: str | None = Field(
        default=None,
        description=(
            "提一个问题，由独立上下文的探查 AI 在归档区里自行查证并给出带引用的答案；"
            "不记得归档在哪、或只需要一个事实性答案时用这个"
        ),
    )
    archives: list[str] | None = Field(
        default=None,
        description=(
            "按句柄展开归档（如 arc-3）：该段完整思考与查证过程取回你的上下文，"
            "供你亲自重看重新判断；单次最多 2 个"
        ),
    )
    ids: list[str] | None = Field(
        default=None,
        description=(
            "按 ID 取原始记录（activity/evidence/relation）的完整字段；单次最多 3 条"
        ),
    )


class RecallProbeBudget:
    """Per-case probe-call counter (``RECALL_PROBE_MAX_CALLS``)."""

    def __init__(self, max_calls: int) -> None:
        self.max_calls = max_calls
        self.used = 0

    @property
    def exhausted(self) -> bool:
        return self.used >= self.max_calls

    def consume(self) -> None:
        self.used += 1


class _ProbeSession:
    """One probe invocation's read-only view over the store, bounded."""

    def __init__(self, store: MemoryStore, *, max_opens: int) -> None:
        self.store = store
        self.max_opens = max_opens
        self.opens = 0
        self.consulted_archives: list[str] = []
        self.consulted_ids: list[str] = []

    def open(self, handle: str) -> dict[str, Any]:
        handle = str(handle or "")
        block = self.store.get_archive(handle)
        if block is None:
            return {
                "error": "archive_not_found",
                "handle": handle,
                "available": self.store.handles(),
            }
        if self.opens >= self.max_opens:
            return {
                "error": "probe_open_budget",
                "message": (
                    f"本次探查最多展开 {self.max_opens} 个归档，已用完；"
                    "请基于已展开的内容作答，或明确说明无法回答"
                ),
            }
        self.opens += 1
        if handle not in self.consulted_archives:
            self.consulted_archives.append(handle)
        return block

    def raw(self, record_id: str) -> dict[str, Any]:
        record_id = str(record_id or "")
        found = self.store.get_raw(record_id)
        if found is None:
            return {
                "error": "record_not_found",
                "record_id": record_id,
                "message": "归档区没有这个 ID 的原始记录",
            }
        if record_id not in self.consulted_ids:
            self.consulted_ids.append(record_id)
        return found


def _probe_tools(session: _ProbeSession) -> list[StructuredTool]:
    def open_archive(handle: str) -> dict[str, Any]:
        """展开一个归档的完整内容（各轮思考原文与全部工具调用事实）。"""
        return session.open(handle)

    def get_raw(record_id: str) -> dict[str, Any]:
        """按记录 ID 取原始记录的完整字段。"""
        return session.raw(record_id)

    return [
        StructuredTool.from_function(
            func=open_archive,
            name="open_archive",
            description="展开一个归档的完整内容（各轮思考原文与全部工具调用事实）。",
        ),
        StructuredTool.from_function(
            func=get_raw,
            name="get_raw",
            description="按记录 ID 取原始记录的完整字段。",
        ),
    ]


def _run_probe(
    question: str,
    store: MemoryStore,
    probe_model_factory: Callable[[], Any] | None,
    settings: RecallSettings,
    emit: Callable[..., None],
) -> dict[str, Any]:
    if probe_model_factory is None:
        return {
            "error": "probe_not_configured",
            "message": "探查模型未配置，请改用 archives/ids 精确取回",
        }
    try:
        probe_model = probe_model_factory()
    except Exception as error:  # unconfigured credentials surface here
        return {
            "error": "probe_unavailable",
            "message": f"探查模型不可用：{type(error).__name__}",
        }

    session = _ProbeSession(store, max_opens=settings.probe_max_opens)
    agent = create_agent(
        probe_model,
        _probe_tools(session),
        system_prompt=PROBE_SYSTEM_PROMPT,
    )
    payload = {
        "question": question,
        "archive_cards": store.card_index(),
    }
    try:
        outcome = agent.invoke(
            {"messages": [HumanMessage(json.dumps(payload, ensure_ascii=False))]},
            config={"recursion_limit": 2 * settings.probe_max_steps + 2},
        )
    except GraphRecursionError:
        emit("recall", "探查步数超限，已中止", {
            "entry": "question", "opens": session.opens, "steps": None,
            "reason": "recursion_limit",
        })
        return {
            "answer": (
                "探查在步数上限内未能形成答案；请用 recall(archives=[…]) 或 "
                "recall(ids=[…]) 精确取回后自行判断"
            ),
            "consulted": {
                "archives": list(session.consulted_archives),
                "ids": list(session.consulted_ids),
            },
            "probe_usage": {"opens": session.opens, "steps": settings.probe_max_steps},
            "truncated": True,
        }

    messages = outcome.get("messages", [])
    answer = next(
        (
            message.content
            for message in reversed(messages)
            if isinstance(message, AIMessage) and isinstance(message.content, str) and message.content
        ),
        "",
    )
    steps = sum(1 for message in messages if isinstance(message, AIMessage))
    tokens = sum(
        int((message.usage_metadata or {}).get("input_tokens", 0) or 0)
        + int((message.usage_metadata or {}).get("output_tokens", 0) or 0)
        for message in messages
        if isinstance(message, AIMessage)
    )
    truncated = False
    if estimate_tokens(answer) > settings.probe_answer_max_tokens:
        answer = _truncate_to_tokens(answer, settings.probe_answer_max_tokens)
        truncated = True
    emit("recall", f"探查完成：{session.opens} 次展开、{steps} 步、{tokens} tokens", {
        "entry": "question",
        "opens": session.opens,
        "steps": steps,
        "tokens": tokens,
        "truncated": truncated,
        "question_preview": question[:160],
    })
    return {
        "answer": answer,
        "consulted": {
            "archives": list(session.consulted_archives),
            "ids": list(session.consulted_ids),
        },
        "probe_usage": {"opens": session.opens, "steps": steps},
        "truncated": truncated,
    }


def _truncate_to_tokens(text: str, token_limit: int) -> str:
    """Deterministic length bound with an explicit, non-silent marker."""
    scale = max(1, int(len(text) * token_limit / max(1, estimate_tokens(text))))
    candidate = text[:scale]
    while candidate and estimate_tokens(candidate + _PROBE_TRUNCATION_NOTE) > token_limit:
        candidate = candidate[: max(1, int(len(candidate) * 0.9))]
    return candidate + _PROBE_TRUNCATION_NOTE


def _expand_archive(block: dict[str, Any]) -> dict[str, Any]:
    rounds = []
    for record in block.get("rounds", []):
        calls = []
        for call in record.get("tool_calls", []):
            ids = call.get("ids") or {}
            expanded_call = {
                "tool": call.get("tool"),
                "args_digest": call.get("args_digest"),
                "returned": call.get("returned"),
            }
            for key, kind in (
                ("activity_ids", "activities"),
                ("evidence_ids", "evidence"),
                ("relation_ids", "relations"),
            ):
                values = ids.get(kind) or []
                if values:
                    expanded_call[key] = values
            if call.get("error"):
                expanded_call["error"] = call["error"]
            calls.append(expanded_call)
        rounds.append(
            {
                "round": record.get("round"),
                "thinking": record.get("thinking"),
                "tool_calls": calls,
            }
        )
    return {
        "archive_id": block["archive_id"],
        "summary": block["summary"],
        "round_span": block["round_span"],
        "rounds": rounds,
    }


def build_recall_tools(
    store: MemoryStore,
    *,
    probe_model_factory: Callable[[], Any] | None = None,
    settings: RecallSettings | None = None,
    probe_budget: RecallProbeBudget | None = None,
    emit: Callable[..., None] | None = None,
) -> list[StructuredTool]:
    """Assemble the ``recall`` tool over one run's memory store.

    ``probe_model_factory`` is lazy: the probe model is only built when the
    question entry actually fires, so assembly never requires credentials.
    """
    config = settings or RecallSettings()
    budget = probe_budget or RecallProbeBudget(config.probe_max_calls)
    sink = emit or (lambda *_args, **_kwargs: None)

    def execute(**arguments: Any) -> dict[str, Any]:
        provided = [
            name for name in ("question", "archives", "ids")
            if arguments.get(name) is not None
        ]
        if len(provided) != 1:
            return {
                "error": "entry_points_exclusive",
                "message": "recall 三种入口（question/archives/ids）每次只能用其中一个",
                "provided": provided,
            }
        if arguments.get("question") is not None:
            question = str(arguments["question"]).strip()
            if not question:
                return {
                    "error": "empty_question",
                    "message": "question 不能为空；按句柄展开用 archives，按 ID 取原文用 ids",
                }
            if budget.exhausted:
                return {
                    "error": "probe_budget_exhausted",
                    "message": "本案探查次数已用尽，请用 archives/ids 精确取回",
                }
            budget.consume()
            return _run_probe(question, store, probe_model_factory, config, sink)

        if arguments.get("archives") is not None:
            handles = [str(handle) for handle in arguments["archives"]]
            if not handles:
                return {
                    "error": "empty_archives",
                    "message": "archives 不能为空列表",
                }
            if len(handles) > config.max_archives:
                return {
                    "error": "too_many_archives",
                    "message": f"单次最多展开 {config.max_archives} 个归档，请分批取回",
                }
            blocks = [(handle, store.get_archive(handle)) for handle in handles]
            found = [block for _, block in blocks if block is not None]
            missing = [handle for handle, block in blocks if block is None]
            sink("recall", f"按句柄展开归档：{len(found)} 个", {
                "entry": "archives",
                "handles": [handle for handle, _ in blocks],
                "missing": missing,
            })
            if not found:
                return {
                    "archives": [],
                    "available": store.handles(),
                    "message": "未找到所询归档，现存归档如下",
                }
            result: dict[str, Any] = {
                "archives": [_expand_archive(block) for block in found],
                "truncated": False,
            }
            if missing:
                result["missing"] = missing
            return result

        record_ids = [str(record_id) for record_id in arguments["ids"]]
        if not record_ids:
            return {"error": "empty_ids", "message": "ids 不能为空列表"}
        if len(record_ids) > config.max_ids:
            return {
                "error": "too_many_ids",
                "message": f"单次最多取 {config.max_ids} 条记录，请分批取回",
            }
        records = [store.get_raw(record_id) for record_id in record_ids]
        found_records = [record for record in records if record is not None]
        missing_ids = [
            record_id for record_id, record in zip(record_ids, records) if record is None
        ]
        sink("recall", f"按 ID 取原始记录：{len(found_records)} 条", {
            "entry": "ids",
            "requested": len(record_ids),
            "missing": len(missing_ids),
        })
        return {
            "records": found_records,
            "missing": missing_ids,
            "truncated": False,
        }

    return [
        StructuredTool.from_function(
            func=execute,
            name=RECALL_TOOL,
            description=RECALL_DESCRIPTION,
            args_schema=RecallInput,
        )
    ]


def build_recall_probe_model(settings: AppSettings):
    """Probe chat model: judgment identity, probe model name, answer budget."""
    recall = settings.recall
    probe_settings = settings.judgment_model.model_copy(
        update={
            "model_name": recall.probe_model_name or settings.judgment_model.model_name,
            "max_tokens": recall.probe_answer_max_tokens,
        }
    )
    return build_chat_model(probe_settings)


def build_recall_probe_model_factory(
    settings: AppSettings,
) -> Callable[[], Any]:
    """Lazy factory so the probe model is built on first question only."""

    def factory() -> Any:
        return build_recall_probe_model(settings)

    return factory


__all__ = [
    "PROBE_SYSTEM_PROMPT",
    "RECALL_TOOL",
    "RecallInput",
    "RecallProbeBudget",
    "build_recall_probe_model",
    "build_recall_probe_model_factory",
    "build_recall_tools",
]
