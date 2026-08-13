from __future__ import annotations

import uuid
import hashlib
from typing import Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph

from ..domain.models import (
    AnalysisRequest,
    DataToolRequest,
    Entity,
    EvidenceBundle,
    EvidenceRequest,
    FactFindingBundle,
    FinishRequest,
    InvestigationAction,
    InvestigationState,
    ScopeExpansion,
    ScopeRequest,
    ToolCall,
    ToolScore,
)
from ...contracts import KnowledgeQuery, KnowledgeResult
from ...knowledge import KnowledgeRetrievalPort, NullKnowledgeRetriever
from .orchestration import (
    add_repair_action,
    apply_pending_repair,
    build_evidence_pack,
    plan_verdict_repairs,
)
from .planner import Planner
from .policy import PolicyError, validate_action
from .state import apply_analysis_bundle, apply_evidence_bundle
from ..adapters.tools import ToolRegistry
from ..adapters.investigation_tools import InvestigationToolGateway
from ..domain.verdict import evaluate_verdict, validate_verdict


Route = Literal["plan", "execute", "scope", "finish", "retry", "continue", "end"]


class JudgmentGraphState(TypedDict, total=False):
    investigation: InvestigationState
    action: InvestigationAction | None
    route: Route
    knowledge_results: list[KnowledgeResult]


class JudgmentGraph:
    """LangGraph runtime for the existing evidence-grounded judgment semantics."""

    def __init__(
        self,
        registry: ToolRegistry,
        planner: Planner,
        *,
        checkpointer: Any = None,
        scope_approval_mode: Literal["legacy", "defer"] = "legacy",
        knowledge_retriever: KnowledgeRetrievalPort | None = None,
        data_tool_gateway: InvestigationToolGateway | None = None,
        report_composer: Any = None,
        recursion_limit: int = 1000,
    ):
        self.registry = registry
        self.planner = planner
        self.scope_approval_mode = scope_approval_mode
        self.knowledge_retriever = knowledge_retriever or NullKnowledgeRetriever()
        self.data_tool_gateway = data_tool_gateway
        self.report_composer = report_composer
        self.recursion_limit = recursion_limit
        builder = StateGraph(JudgmentGraphState)
        builder.add_node("load_knowledge_context", self._load_knowledge_context)
        builder.add_node("prepare_iteration", self._prepare_iteration)
        builder.add_node("plan_action", self._plan_action)
        builder.add_node("validate_action", self._validate_action)
        builder.add_node("execute_action", self._execute_action)
        builder.add_node("handle_scope", self._handle_scope)
        builder.add_node("evaluate_verdict", self._evaluate_verdict)
        builder.add_edge(START, "load_knowledge_context")
        builder.add_edge("load_knowledge_context", "prepare_iteration")
        builder.add_conditional_edges(
            "prepare_iteration",
            lambda value: value["route"],
            {"plan": "plan_action", "end": END},
        )
        builder.add_edge("plan_action", "validate_action")
        builder.add_conditional_edges(
            "validate_action",
            lambda value: value["route"],
            {
                "execute": "execute_action",
                "scope": "handle_scope",
                "finish": "evaluate_verdict",
                "retry": "prepare_iteration",
            },
        )
        builder.add_conditional_edges(
            "execute_action",
            lambda value: value["route"],
            {"continue": "prepare_iteration", "end": END},
        )
        builder.add_conditional_edges(
            "handle_scope",
            lambda value: value["route"],
            {"continue": "prepare_iteration", "end": END},
        )
        builder.add_conditional_edges(
            "evaluate_verdict",
            lambda value: value["route"],
            {"continue": "prepare_iteration", "end": END},
        )
        self.compiled = builder.compile(checkpointer=checkpointer)

    def run(
        self,
        state: InvestigationState,
        *,
        config: dict[str, Any] | None = None,
    ) -> InvestigationState:
        graph_config: dict[str, Any] = {"recursion_limit": self.recursion_limit}
        if config:
            graph_config.update(config)
        result = self.compiled.invoke(
            {
                "investigation": state.model_copy(deep=True),
                "action": None,
                "route": "plan",
                "knowledge_results": [],
            },
            config=graph_config,
        )
        return InvestigationState.model_validate(result["investigation"])

    def _load_knowledge_context(self, graph_state: JudgmentGraphState) -> JudgmentGraphState:
        state = graph_state["investigation"]
        topic = ", ".join(state.active_scenarios) or "unknown-file investigation"
        fingerprint = hashlib.sha256(f"{state.case_id}:{topic}".encode()).hexdigest()[:16]
        result = self.knowledge_retriever.retrieve(
            KnowledgeQuery(
                tenant_id=str(state.raw_input.get("tenant_id") or "default"),
                case_id=state.case_id,
                source_identity="judgment-graph",
                query_id=f"kquery-{fingerprint}",
                knowledge_domain="investigation",
                query_text=f"Investigation guidance for active scenarios: {topic}",
            )
        )
        return {"knowledge_results": [result]}

    def _prepare_iteration(self, graph_state: JudgmentGraphState) -> JudgmentGraphState:
        state = graph_state["investigation"].model_copy(deep=True)
        if state.finished:
            return {"investigation": state, "action": None, "route": "end"}
        state.budget.iterations_used += 1
        if (
            state.budget.max_iterations - state.budget.iterations_used <= 3
            and not any(item.repair_type == "converge_under_budget" for item in state.repair_actions)
        ):
            repair = add_repair_action(
                state,
                repair_type="converge_under_budget",
                trigger="budget_near_exhaustion",
                reason="Prioritize mandatory unresolved gaps and avoid optional low-information queries",
                blocking=False,
            )
            repair.status = "applied"
        catalog = self.registry.catalog(state)
        state.tool_scores.extend(
            ToolScore.model_validate(item["score_breakdown"])
            for item in catalog
            if not any(
                existing.iteration == state.budget.iterations_used
                and existing.tool_name == item["tool_name"]
                for existing in state.tool_scores
            )
        )
        if state.budget.iterations_used > state.budget.max_iterations:
            state.verdict = evaluate_verdict(state)
            state.verdict.limitations.append(
                "Investigation stopped because the iteration budget was exhausted"
            )
            state.finished = True
            return {"investigation": state, "action": None, "route": "end"}
        return {"investigation": state, "action": None, "route": "plan"}

    def _plan_action(self, graph_state: JudgmentGraphState) -> JudgmentGraphState:
        state = graph_state["investigation"].model_copy(deep=True)
        plan_with_knowledge = getattr(self.planner, "plan_with_knowledge", None)
        action = (
            plan_with_knowledge(state, list(graph_state.get("knowledge_results") or []))
            if plan_with_knowledge is not None
            else self.planner.plan(state)
        )
        return {"investigation": state, "action": action, "route": "plan"}

    def _validate_action(self, graph_state: JudgmentGraphState) -> JudgmentGraphState:
        state = graph_state["investigation"].model_copy(deep=True)
        action = graph_state.get("action")
        if action is None:
            raise RuntimeError("Planner produced no investigation action")
        try:
            validate_action(
                action, state, self.registry,
                data_tool_mode=bool(getattr(self.planner, "uses_data_tools", False)),
            )
        except (PolicyError, KeyError) as first_error:
            repair_record = add_repair_action(
                state,
                repair_type="repair_invalid_action",
                trigger="policy_validation_failed",
                target_gap_id=getattr(action, "gap_id", None),
                recommended_tools=[],
                reason=str(first_error),
                blocking=True,
            )
            repair = getattr(self.planner, "repair", None)
            if repair is not None:
                try:
                    action = repair(state, action, str(first_error))
                    validate_action(
                        action, state, self.registry,
                        data_tool_mode=bool(getattr(self.planner, "uses_data_tools", False)),
                    )
                    repair_record.status = "applied"
                    repair_record.attempts = 1
                except Exception as repair_error:
                    self._record_denied(
                        state,
                        action,
                        f"Repair failed: {type(repair_error).__name__}: {repair_error}",
                    )
                    return {"investigation": state, "action": None, "route": "retry"}
            else:
                self._record_denied(state, action, str(first_error))
                self._fail_matching_obligations(state, action, str(first_error))
                return {"investigation": state, "action": None, "route": "retry"}
        if isinstance(action, FinishRequest):
            route: Route = "finish"
        elif isinstance(action, ScopeRequest):
            route = "scope"
        else:
            route = "execute"
        return {"investigation": state, "action": action, "route": route}

    def _handle_scope(self, graph_state: JudgmentGraphState) -> JudgmentGraphState:
        state = graph_state["investigation"].model_copy(deep=True)
        action = graph_state.get("action")
        if not isinstance(action, ScopeRequest):
            raise RuntimeError("Scope node requires ScopeRequest")
        approved = state.scope.expansion_policy == "automatic"
        expansion = ScopeExpansion(
            expansion_id=f"scope-{uuid.uuid4().hex[:10]}",
            candidate_host_ids=list(dict.fromkeys(action.requested_host_ids)),
            reason_type=action.reason_type,
            reason_evidence_refs=action.reason_evidence_refs,
            requested_domains=action.requested_domains,
            start_time=action.start_time,
            end_time=action.end_time,
            approval_status="pending",
            approval_source="policy:auto" if approved else "human_approval_required",
            limitations=[],
        )
        state.scope_expansions.append(expansion)
        if not approved and self.scope_approval_mode == "defer":
            return {"investigation": state, "action": None, "route": "end"}
        self.apply_scope_decision(
            state,
            approved=approved,
            approval_source="policy:auto" if approved else "policy:legacy-denial",
            objective=action.objective,
        )
        return {"investigation": state, "action": None, "route": "continue"}

    @staticmethod
    def apply_scope_decision(
        state: InvestigationState,
        *,
        approved: bool,
        approval_source: str,
        objective: str = "Resolve requested investigation scope expansion",
    ) -> InvestigationState:
        expansion = next(
            (item for item in reversed(state.scope_expansions) if item.approval_status == "pending"),
            None,
        )
        if expansion is None:
            raise ValueError("No pending scope expansion exists")
        expansion.approval_status = "approved" if approved else "denied"
        expansion.approval_source = approval_source
        expansion.limitations = [] if approved else [
            "Scope was not expanded because explicit approval was denied"
        ]
        if approved:
            for host_id in expansion.candidate_host_ids:
                if host_id not in state.scope.host_ids:
                    state.scope.host_ids.append(host_id)
                entity_id = f"host:{host_id}"
                if not any(item.entity_id == entity_id for item in state.entities):
                    state.entities.append(
                        Entity(
                            entity_id=entity_id,
                            entity_type="host",
                            attributes={"scope_expansion": expansion.expansion_id},
                        )
                    )
            state.budget.scope_expansions_used += 1
        else:
            for gap in state.evidence_gaps:
                if gap.gap_type in {"cross_host_confirmation", "cross_host_counter"}:
                    gap.status = "unresolvable"
                    gap.resolution = "unresolvable"
                    gap.limitations.append(
                        "Candidate host was not added because scope approval was denied"
                    )
                elif gap.gap_type == "cross_host_lead":
                    gap.status = "resolved"
                    gap.resolution = "positive"
                    gap.resolution_refs = list(expansion.reason_evidence_refs)
            repair = add_repair_action(
                state,
                repair_type="respect_scope_denial",
                trigger="scope_approval_denied",
                reason="Do not query target-host evidence after explicit scope denial",
                reason_evidence_refs=expansion.reason_evidence_refs,
                blocking=False,
            )
            repair.status = "applied"
        state.tool_calls.append(
            ToolCall(
                call_id=f"call-{uuid.uuid4().hex[:10]}",
                tool_name="scope_request",
                action_type="scope_request",
                status="success" if approved else "denied",
                objective=objective,
                parameters={
                    "requested_host_ids": expansion.candidate_host_ids,
                    "reason_evidence_refs": expansion.reason_evidence_refs,
                    "reason_type": expansion.reason_type,
                    "requested_domains": expansion.requested_domains,
                },
                error=None if approved else "Scope expansion was denied",
            )
        )
        return state

    def _execute_action(self, graph_state: JudgmentGraphState) -> JudgmentGraphState:
        state = graph_state["investigation"].model_copy(deep=True)
        action = graph_state.get("action")
        if not isinstance(action, (EvidenceRequest, AnalysisRequest, DataToolRequest)):
            raise RuntimeError("Execution node requires an evidence, analysis or data-tool request")
        call_parameters = (
            {"evidence_refs": sorted(set(action.evidence_refs))}
            if isinstance(action, AnalysisRequest)
            else action.arguments
            if isinstance(action, DataToolRequest)
            else {"gap_id": action.gap_id, **action.parameters}
        )
        call = ToolCall(
            call_id=f"call-{uuid.uuid4().hex[:10]}",
            tool_name=action.tool_name,
            action_type=action.action_type,
            status="success",
            objective=action.objective,
            parameters=call_parameters,
        )
        matching_obligations = []
        if isinstance(action, AnalysisRequest):
            matching_obligations = [
                item
                for item in state.analysis_obligations
                if item.tool_name == action.tool_name
                and item.status == "pending"
                and set(item.evidence_refs) == set(action.evidence_refs)
            ]
            for obligation in matching_obligations:
                obligation.status = "running"
                for gap in state.evidence_gaps:
                    if gap.gap_id in obligation.gap_ids:
                        gap.status = "analyzing"
        try:
            if isinstance(action, DataToolRequest):
                if self.data_tool_gateway is None:
                    raise PolicyError("LLM data-tool gateway is not configured")
                from ...contracts import ToolRuntimeContext
                self.data_tool_gateway.invoke(
                    action.tool_name,
                    action.arguments,
                    ToolRuntimeContext(
                        tenant_id=str(state.raw_input.get("tenant_id") or "default"),
                        case_id=state.case_id,
                        run_id=str(state.raw_input.get("run_id") or "primary"),
                        scope=state.scope,
                    ),
                    state.tool_ledger,
                    tool_call_id=action.tool_call_id,
                    model_message=action.model_message,
                )
                state.budget.tool_calls_used += 1
                state.tool_calls.append(call)
                return {"investigation": state, "action": None, "route": "continue"}
            invocation_parameters = (
                action.parameters
                if isinstance(action, EvidenceRequest)
                else {"evidence_refs": sorted(set(action.evidence_refs))}
            )
            result = self.registry.invoke(action.tool_name, state, invocation_parameters)
            state.budget.tool_calls_used += 1
            if isinstance(result, EvidenceBundle):
                requested_types = self.registry.get(action.tool_name).provides_evidence_types
                apply_evidence_bundle(state, result, self.registry, requested_types)
                state.evidence_packs.append(
                    build_evidence_pack(
                        state,
                        call.call_id,
                        action.tool_name,
                        action.gap_id,
                        action.parameters,
                        result,
                    )
                )
                if not result.evidence and result.coverage.completeness != "complete":
                    gap = next(item for item in state.evidence_gaps if item.gap_id == action.gap_id)
                    remaining = [
                        name
                        for name in gap.recommended_tools
                        if not any(item.tool_name == name for item in state.tool_calls)
                    ]
                    if remaining:
                        add_repair_action(
                            state,
                            repair_type="use_alternative_source",
                            trigger="empty_result_with_incomplete_coverage",
                            target_gap_id=gap.gap_id,
                            recommended_tools=remaining,
                            reason=(
                                "The query returned no evidence, but Coverage is not complete; "
                                "absence cannot be concluded"
                            ),
                        )
                for repair_action in state.repair_actions:
                    if (
                        repair_action.status == "pending"
                        and action.tool_name in repair_action.recommended_tools
                    ):
                        repair_action.status = "applied"
                        repair_action.attempts += 1
                        state.budget.repair_actions_used += 1
                if result.status.value in {"empty", "partial", "unavailable", "error"}:
                    call.status = result.status.value
            elif isinstance(result, FactFindingBundle):
                apply_analysis_bundle(state, result, action.tool_name, action.evidence_refs)
        except (PolicyError, KeyError) as exc:
            call.status, call.error = "denied", str(exc)
        except Exception as exc:
            call.status, call.error = "error", f"{type(exc).__name__}: {exc}"
            if isinstance(action, DataToolRequest) and self.data_tool_gateway is not None:
                from ...contracts import InvestigationToolTrace
                state.tool_ledger.traces.append(InvestigationToolTrace(
                    sequence=len(state.tool_ledger.traces) + 1,
                    tool_name=action.tool_name,
                    arguments=action.arguments,
                    result_type="ToolError",
                    result={"error_type": type(exc).__name__, "error_message": str(exc)},
                    tool_call_id=action.tool_call_id,
                    model_message=action.model_message,
                ))
                self.data_tool_gateway.event_sink("tool_error", "数据工具调用失败", {
                    "tool_name": action.tool_name,
                    "tool_call_id": action.tool_call_id,
                    "arguments": action.arguments,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                })
            add_repair_action(
                state,
                repair_type=(
                    "complete_analyzer_inputs"
                    if isinstance(action, AnalysisRequest)
                    else "use_alternative_source"
                ),
                trigger="tool_execution_failed",
                target_gap_id=getattr(action, "gap_id", None),
                reason=call.error,
                blocking=isinstance(action, AnalysisRequest),
            )
        if call.status in {"denied", "error"}:
            for obligation in matching_obligations:
                obligation.status = "failed"
                obligation.limitations.append(call.error or "Analysis execution failed")
                for gap in state.evidence_gaps:
                    if gap.gap_id in obligation.gap_ids:
                        gap.status = "partially_resolved"
        state.tool_calls.append(call)
        self._resolve_exhausted_alternative_gaps(state)
        route: Route = "continue"
        if state.budget.iterations_used >= state.budget.max_iterations:
            state.verdict = evaluate_verdict(state)
            state.verdict.limitations.append(
                "Investigation stopped because the iteration budget was exhausted"
            )
            state.finished = True
            route = "end"
        return {"investigation": state, "action": None, "route": route}

    def _evaluate_verdict(self, graph_state: JudgmentGraphState) -> JudgmentGraphState:
        state = graph_state["investigation"].model_copy(deep=True)
        state.verdict = evaluate_verdict(state)
        errors = validate_verdict(state, state.verdict)
        state.verdict_validation_errors = list(errors)
        if errors:
            repairs = plan_verdict_repairs(state, errors)
            applied = (
                apply_pending_repair(state, {item.repair_id for item in repairs})
                if repairs
                else None
            )
            if applied and applied.status == "applied":
                state.budget.verdict_repairs_used += 1
                state.verdict = None
                state.verdict_validation_errors = []
                return {"investigation": state, "action": None, "route": "continue"}
            state.verdict.limitations.extend(errors)
            state.verdict.level = "insufficient_evidence"
        if self.report_composer is not None:
            report = self.report_composer.compose(state)
            report_errors = self.report_composer.validate(state, report)
            attempts = 0
            while report_errors and attempts < state.budget.max_verdict_repairs:
                attempts += 1
                report = self.report_composer.repair(state, report, report_errors)
                report_errors = self.report_composer.validate(state, report)
            state.report_validation_errors = list(report_errors)
            if report_errors:
                report.limitations.extend(report_errors)
                report.verdict.level = "insufficient_evidence"
            state.investigation_report = report
            state.verdict = report.verdict
        state.finished = True
        return {"investigation": state, "action": None, "route": "end"}

    @staticmethod
    def _record_denied(state: InvestigationState, action: InvestigationAction, error: str) -> None:
        state.tool_calls.append(
            ToolCall(
                call_id=f"call-{uuid.uuid4().hex[:10]}",
                tool_name=getattr(action, "tool_name", None) or action.action_type,
                action_type=action.action_type,
                status="denied",
                objective=action.objective,
                parameters=action.model_dump(
                    mode="json", exclude={"action_type", "tool_name", "objective"}
                ),
                error=error,
            )
        )

    @staticmethod
    def _fail_matching_obligations(
        state: InvestigationState, action: InvestigationAction, error: str
    ) -> None:
        if not isinstance(action, AnalysisRequest):
            return
        selected = set(action.evidence_refs)
        for obligation in state.analysis_obligations:
            if (
                obligation.status == "pending"
                and obligation.tool_name == action.tool_name
                and set(obligation.evidence_refs) == selected
            ):
                obligation.status = "failed"
                obligation.limitations.append(error)

    def _resolve_exhausted_alternative_gaps(self, state: InvestigationState) -> None:
        attempted = {
            call.tool_name for call in state.tool_calls if call.status not in {"denied", "error"}
        }
        available_types = {
            item.evidence_type for item in state.evidence if item.status.value == "available"
        }
        registered = {item.name for item in self.registry.list()}
        for gap in state.evidence_gaps:
            if gap.requirement_mode != "any" or gap.status != "partially_resolved":
                continue
            relevant_tools = [name for name in gap.recommended_tools if name in registered]
            if (
                relevant_tools
                and set(relevant_tools) <= attempted
                and not (set(gap.required_evidence_types) & available_types)
            ):
                gap.status = "resolved"
                gap.resolution = "negative"
