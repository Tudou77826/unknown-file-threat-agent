"""The official create_agent-based judgment runtime.

The investigation loop uses the framework-recommended create_agent API and
reusable middlewares. Business collaborators — the typed boundary policy, the
data-tool gateway and the report pipeline — are injected through stable
ports; CaseGraph consumes only the compiled subgraph contract.

Middleware stacking order (first = outermost):

1. ``BudgetMiddleware`` — multi-dimension budget; exhaustion raises the
   stop signal, caught here to run the degradation path (report from
   whatever was already queried, mirroring the graph's forced finish).
2. ``HistoryHygieneMiddleware`` — normalizes provider streaming artifacts
   in history before any model call (one malformed block must not crash
   the next request).
3. official ``SummarizationMiddleware`` — history-level compaction shell
   (fallback when the archive rhythm fails; its firing is the alert).
4. ``ReducerMiddleware`` — deterministic tool-result downsizing; original
   content preserved in the message artifact.
5. ``ArchiveMiddleware`` — model-driven interval archiving into the run's
   ``MemoryStore``; its own tool never reaches the data boundary.
6. ``BoundaryMiddleware`` (innermost) — its post-execution validation sees
   the original tool result before the reducer downsizes it.

The ``recall`` tool (question probe / handle expansion / ID fetch) reads the
same ``MemoryStore`` and is registered alongside the gateway tools.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable, TypedDict

from langchain.agents import create_agent
from langchain.agents.middleware import SummarizationMiddleware
from langchain_core.callbacks import BaseCallbackHandler
from langgraph.graph import END, START, StateGraph

from ..agent_middleware import (
    ArchiveMiddleware,
    BudgetExhausted,
    HistoryHygieneMiddleware,
    MiddlewareEvent,
    SafetyNetMiddleware,
)
from ..case_management import SingleHostBoundaryPolicy
from ..contracts import InvestigationToolLedger, ToolRuntimeContext
from ..judgment.adapters.knowledge_tools import knowledge_scenario_tools
from ..judgment.application.data_tool_planner import planner_system_prompt
from ..judgment.application.graph import publish_investigation_report
from ..judgment.application.knowledge_baseline import run_knowledge_baseline
from ..judgment.application.memory_store import MemoryStore
from ..judgment.domain.models import InvestigationState
from ..knowledge import NullKnowledgeSupplier, SecurityKnowledgeService
from .memory_tools import (
    RecallProbeBudget,
    build_recall_probe_model_factory,
    build_recall_tools,
)
from .middleware_bindings import (
    boundary_middleware_for,
    budget_middleware_for,
    brief_reducer_middleware,
    investigation_gateway_tools,
)
from .settings import AppSettings, ArchiveSettings, RecallSettings

EventSink = Callable[[str, str, dict[str, Any] | None], None]


class LlmEventBridge(BaseCallbackHandler):
    """Bridge LLM calls and tool executions inside the agent loop into the run
    event ledger.

    Responsibilities:
    - one ``model_input``/``model_output`` event per planning call (with token
      usage and latency) so every model call is replayable;
    - one ``round`` event per investigation round, closing the tools executed
      since the previous planning call — this is the narrative spine the
      workbench groups by.
    """

    # tool name -> human label for the round observation sentence
    _TOOL_ZH = {
        "query_process_activities": "进程与命令",
        "query_network_activities": "网络连接",
        "query_socket_activities": "网络收发",
        "query_file_activities": "文件变更",
        "query_service_activities": "系统服务",
        "query_package_activities": "软件包来源",
        "query_asset_activities": "资产基线",
        "explore_entity": "实体关联",
        "get_raw_records": "原始记录",
        "calculate_activity_metrics": "活动统计",
        "lookup_attack_technique": "攻击技术库",
        "consult_judgment_experience": "研判经验库",
        "interpret_telemetry_field": "遥测字段说明",
    }

    _PHASE_LABEL = {
        "judgment_planning": "研判规划",
        "judgment_report": "研判报告",
        "response_advisory": "处置建议",
    }

    def __init__(self, emit, phase: str = "judgment_planning", node: str = "plan"):
        self.emit = emit
        self.phase = phase
        self.node = node
        self.label = self._PHASE_LABEL.get(phase, phase)
        self._starts: dict[str, float] = {}
        self._round_tools: list[tuple[str, bool]] = []
        self._round_index = 0

    # -- LLM ---------------------------------------------------------------

    def on_llm_start(self, serialized, prompts, *, run_id=None, **kwargs):
        import time as _time

        # Tools finished since the previous planning call constitute one
        # completed investigation round: close it before the next call starts.
        self._close_round()
        if run_id is not None:
            self._starts[str(run_id)] = _time.perf_counter()
        try:
            preview = json.dumps(prompts, ensure_ascii=False, default=str)[:4000]
        except Exception:
            preview = "[]"
        self.emit("model_input", f"{self.label}模型输入", {
            "phase": self.phase, "node": self.node, "preview": preview,
        })

    def on_llm_end(self, response, *, run_id=None, **kwargs):
        import time as _time

        duration_ms = None
        if run_id is not None and str(run_id) in self._starts:
            duration_ms = round((_time.perf_counter() - self._starts.pop(str(run_id))) * 1000, 1)
        usage: dict[str, int] = {}
        try:
            raw = (response.llm_output or {}).get("token_usage") or {}
            usage = {k: int(v) for k, v in raw.items() if isinstance(v, (int, float))}
        except Exception:
            usage = {}
        if not usage:
            # Anthropic-family clients carry usage on the message itself.
            try:
                message = response.generations[0][0].message
                meta = getattr(message, "usage_metadata", None) or {}
                usage = {k: int(v) for k, v in meta.items() if isinstance(v, (int, float))}
            except Exception:
                usage = {}
        self.emit("model_output", f"{self.label}模型输出", {
            "phase": self.phase, "node": self.node,
            "token_usage": usage, "duration_ms": duration_ms,
        })

    def on_llm_error(self, error, *, run_id=None, **kwargs):
        self.emit("model_output", f"{self.label}模型调用失败", {
            "phase": self.phase, "node": self.node,
            "error_type": type(error).__name__, "error_message": str(error)[:400],
        })

    # -- tools -------------------------------------------------------------

    def on_tool_start(self, serialized, input_str, *, name=None, **kwargs):
        tool = name or (serialized or {}).get("name") or "tool"
        self._round_tools.append((str(tool), False))

    def on_tool_error(self, error, *, name=None, **kwargs):
        tool = name or "tool"
        if self._round_tools:
            self._round_tools[-1] = (tool, True)

    # -- round closure -----------------------------------------------------

    def flush_round(self) -> None:
        """Close the trailing round after the agent loop ends."""
        self._close_round()

    def _close_round(self) -> None:
        if not self._round_tools:
            return
        tools, failed = list(self._round_tools), []
        self._round_tools = []
        self._round_index += 1
        labels: list[str] = []
        for tool, is_error in tools:
            label = self._TOOL_ZH.get(tool, tool)
            if label not in labels:
                labels.append(label)
            if is_error:
                failed.append(label)
        observation = (
            f"第 {self._round_index} 轮：查询了" + "、".join(labels[:4])
            + (f" 等 {len(labels)} 类" if len(labels) > 4 else "")
            + "。"
        )
        if failed:
            observation += f"其中{ '、'.join(sorted(set(failed))) }被拒绝，模型据此调整了下一步。"
        self.emit("round", observation, {
            "node": "execute",
            "round": self._round_index,
            "observation": observation,
            "tool_names": [tool for tool, _ in tools],
        })


def _middleware_event_sink(emit: EventSink) -> Callable[[MiddlewareEvent], None]:
    """Translate middleware events into the demo's operational event stream."""

    def sink(event: MiddlewareEvent) -> None:
        if event.kind == "boundary_denied":
            emit("tool_error", f"调查边界拒绝工具调用：{event.tool_name}", {
                "node": "execute",
                "tool_name": event.tool_name,
                "error_type": "BoundaryDenied",
                **event.detail,
            })
        elif event.kind == "budget_denied":
            emit("tool_error", f"预算拒绝工具调用：{event.tool_name}", {
                "node": "execute",
                "tool_name": event.tool_name,
                "error_type": "BudgetDenied",
                **event.detail,
            })
        elif event.kind == "budget_exhausted":
            emit("gate", "预算耗尽，使用已获数据降级生成报告", {
                "node": "gate",
                "error_dimension": event.detail.get("error_dimension"),
                "orchestration": "framework_middleware",
            })
        elif event.kind == "reducer_applied":
            emit("context", "工具结果已确定性降采样后进入模型上下文", {
                "node": "execute",
                **event.detail,
            })
        elif event.kind == "archive_recorded":
            emit("context", "上下文归档已登记，待下一次模型调用前重写", {
                "node": "execute",
                **event.detail,
            })
        elif event.kind == "archive_applied":
            emit("context", "上下文区间已归档，原位留卡", {
                "node": "execute",
                **event.detail,
            })
        elif event.kind == "archive_denied":
            emit("context", "归档请求被确定性护栏拒绝", {
                "node": "execute",
                **event.detail,
            })
        elif event.kind == "tool_chain_error":
            emit("tool_error", "工具执行链意外错误已转为可观测错误", {
                "node": "execute",
                **event.detail,
            })

    return sink


class _RunnerState(TypedDict, total=False):
    investigation: InvestigationState


class MiddlewareJudgmentRunner:
    """Canonical judgment runtime on create_agent plus middlewares."""

    def __init__(
        self,
        *,
        model: Any,
        summarizer_model: Any,
        gateway: Any,
        boundary_policy: SingleHostBoundaryPolicy,
        context: ToolRuntimeContext,
        ledger: InvestigationToolLedger,
        case_budget,
        report_composer,
        report_coordinator=None,
        report_validator=None,
        report_publisher=None,
        knowledge_service: SecurityKnowledgeService | None = None,
        settings: AppSettings | None = None,
        memory_store: MemoryStore | None = None,
        emit: EventSink | None = None,
        context_window_tokens: int = 100_000,
        summarization_trigger_pct: float = 0.70,
        recursion_limit: int = 1000,
    ):
        self.tenant_id = context.tenant_id
        self.run_id = context.run_id
        self.ledger = ledger
        self.case_budget = case_budget
        self.report_composer = report_composer
        self.report_coordinator = report_coordinator
        self.report_validator = report_validator
        self.report_publisher = report_publisher
        # 未配置部署默认走 Null 供应方：基线检索仍执行并显式记录 not_configured
        self.knowledge_service = knowledge_service or SecurityKnowledgeService(
            NullKnowledgeSupplier()
        )
        self.emit = emit or (lambda _kind, _message, _details=None: None)
        self.recursion_limit = recursion_limit

        archive_settings = (
            settings.archive if settings is not None else ArchiveSettings()
        )
        recall_settings = (
            settings.recall if settings is not None else RecallSettings()
        )
        # Run-scoped archive memory: written by ArchiveMiddleware, read by the
        # recall entries and the report composer (v2 report input). demo
        # assembly shares one instance across the composer and this runner;
        # standalone construction creates its own.
        self.memory_store = memory_store or MemoryStore()
        self.recall_probe_budget = RecallProbeBudget(recall_settings.probe_max_calls)

        sink = _middleware_event_sink(self.emit)
        tools = (
            investigation_gateway_tools(gateway, context, ledger)
            + knowledge_scenario_tools(self.knowledge_service, ledger, event_sink=self.emit)
            + build_recall_tools(
                self.memory_store,
                probe_model_factory=(
                    build_recall_probe_model_factory(settings)
                    if settings is not None
                    else None
                ),
                settings=recall_settings,
                probe_budget=self.recall_probe_budget,
                emit=self.emit,
            )
        )
        middlewares = [
            # 最外层安全网：工具执行链上任何意外异常（含 provider 畸形调用触发的
            # 中间件内部错误）转为可观测错误，不再杀死整案；BudgetExhausted 是
            # 熔断信号，允许穿透。
            SafetyNetMiddleware(on_event=sink),
            budget_middleware_for(case_budget, on_event=sink),
            # Provider streaming artifacts in history (e.g. a malformed tool
            # call's partial_json=None block) crash the next request's JSON
            # formatting; normalize them before any model call.
            HistoryHygieneMiddleware(),
            SummarizationMiddleware(
                summarizer_model,
                trigger=(
                    "tokens",
                    int(context_window_tokens * summarization_trigger_pct),
                ),
            ),
            brief_reducer_middleware(on_event=sink),
            ArchiveMiddleware(
                self.memory_store,
                min_span_rounds=archive_settings.min_span_rounds,
                min_span_tokens=archive_settings.min_span_tokens,
                on_event=sink,
            ),
            boundary_middleware_for(boundary_policy, context, ledger, on_event=sink),
        ]
        memory_contract = (
            settings.application.memory_contract_prompt
            if settings is not None else True
        )
        self.agent = create_agent(
            model,
            tools,
            middleware=middlewares,
            system_prompt=planner_system_prompt(memory_contract=memory_contract),
        )
        builder = StateGraph(_RunnerState)
        builder.add_node("run", self._run_node)
        builder.add_edge(START, "run")
        builder.add_edge("run", END)
        self.compiled = builder.compile()

    # -- CaseGraph subgraph interface ---------------------------------------

    def run(self, state: InvestigationState) -> InvestigationState:
        result = self.compiled.invoke(
            {"investigation": state.model_copy(deep=True)},
            config={"recursion_limit": self.recursion_limit,
                    "callbacks": [LlmEventBridge(self.emit)]},
        )
        return InvestigationState.model_validate(result["investigation"])

    # -- internals -----------------------------------------------------------

    def _initial_message(self, state: InvestigationState) -> str:
        """Case briefing equivalent to the graph planner's case context."""
        payload = {
            "案件输入": {
                key: value
                for key, value in state.raw_input.items()
                if key in {"File_id", "File_hash", "File_path", "Sub_asset", "discovery_time"}
            },
            "授权调查范围": {
                "host_ids": list(state.scope.host_ids),
                "start_time": state.scope.start_time.isoformat()
                if state.scope.start_time
                else None,
                "end_time": state.scope.end_time.isoformat()
                if state.scope.end_time
                else None,
            },
            "初始已授权实体": list(self.ledger.authorized_entity_refs),
        }
        return (
            "请开始调查以下未知文件告警。授权范围与初始实体如下，"
            "请规划第一批数据工具调用：\n" + json.dumps(payload, ensure_ascii=False, default=str)
        )

    def _run_node(self, graph_state: dict[str, Any]) -> dict[str, Any]:
        state: InvestigationState = graph_state["investigation"].model_copy(deep=True)
        self.emit("graph", "AI 已就绪：正在规划第一批取证查询", {
            "node": "intake",
            "orchestration": "framework_middleware",
            "middlewares": [
                "BudgetMiddleware", "HistoryHygieneMiddleware",
                "SummarizationMiddleware", "ReducerMiddleware",
                "ArchiveMiddleware", "BoundaryMiddleware",
            ],
            "case_id": state.case_id,
        })
        started = time.perf_counter()
        degraded = False
        try:
            bridge = LlmEventBridge(self.emit)
            try:
                outcome = self.agent.invoke(
                    {"messages": [("user", self._initial_message(state))]},
                    config={"recursion_limit": self.recursion_limit, "callbacks": [bridge]},
                )
            finally:
                # Even a failed run must close its trailing round: the round
                # narrative is exactly what a failure investigation needs.
                bridge.flush_round()
            model_rounds = sum(
                1
                for message in outcome.get("messages", [])
                if getattr(message, "type", "") == "ai"
            )
        except BudgetExhausted as exhausted:
            degraded = True
            model_rounds = max(1, self.case_budget.max_iterations)
            self.emit("gate", f"预算熔断：{exhausted}", {
                "node": "gate",
                "error_type": "BudgetExhausted",
                "error_dimension": exhausted.dimension,
                "orchestration": "framework_middleware",
            })
        duration_ms = round((time.perf_counter() - started) * 1000, 3)

        # The binding ledger is the single typed record of the run; merge it
        # back into the state the report pipeline and read models consume.
        state.tool_ledger = self.ledger
        state.budget.tool_calls_used = len(self.ledger.traces)
        state.budget.iterations_used = model_rounds
        self.emit("graph", "取证完成，开始形成研判结论", {
            "node": "compose",
            "orchestration": "framework_middleware",
            "model_rounds": model_rounds,
            "tool_traces": len(self.ledger.traces),
            "degraded": degraded,
            "duration_ms": duration_ms,
        })

        # 固定基线检索：证据包组装完成后、报告发布前必定执行一次；
        # 不可用时显式降级记录，不阻断基于安全遥测的报告流程。
        guidance = run_knowledge_baseline(state, self.knowledge_service)
        baseline_record = state.tool_ledger.knowledge_consultations[-1]
        self.emit("knowledge", f"基线知识检索完成：{baseline_record.status}", {
            "node": "compose",
            "entry": "baseline",
            "status": baseline_record.status,
            "consultation_id": baseline_record.consultation_id,
            "query_id": baseline_record.query_id,
            "guidance_items": len(guidance),
            # 命中条目清单（标识+标题，不含正文）：与按需工具的事件明细同构，
            # 运行页知识面板据此展示；正文留在模型上下文与账本 item_refs。
            "items": [
                {
                    "knowledge_id": item.knowledge_id,
                    "version": item.version,
                    "source_category": item.source_category,
                    "title": item.title,
                }
                for item in guidance
            ],
            "limitations": baseline_record.limitations,
        })

        report = publish_investigation_report(
            state,
            self.report_composer,
            validator=self.report_validator,
            coordinator=self.report_coordinator,
            publisher=self.report_publisher,
            tenant_id=self.tenant_id,
            run_id=self.run_id,
        )
        state.investigation_report = report
        state.verdict = report.verdict
        state.finished = True
        return {"investigation": state}
