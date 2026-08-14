from __future__ import annotations

import uuid
from typing import Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph

from ..domain.models import (
    DataToolRequest,
    Entity,
    FinishRequest,
    InvestigationAction,
    InvestigationState,
    ScopeExpansion,
    ScopeRequest,
    ToolCall,
)
from .policy import PolicyError, validate_action


Route = Literal["plan", "execute", "scope", "finish", "retry", "continue", "validate", "end"]


class JudgmentGraphState(TypedDict, total=False):
    investigation: InvestigationState
    action: InvestigationAction | None
    pending_actions: list[InvestigationAction]
    route: Route


class JudgmentGraph:
    """LangGraph runtime for the data-tool driven AI judgment loop."""

    def __init__(
        self,
        planner,
        *,
        checkpointer: Any = None,
        scope_approval_mode: Literal["defer"] = "defer",
        data_tool_gateway=None,
        report_composer=None,
        recursion_limit: int = 1000,
    ):
        self.planner = planner
        self.scope_approval_mode = scope_approval_mode
        self.data_tool_gateway = data_tool_gateway
        self.report_composer = report_composer
        self.recursion_limit = recursion_limit
        builder = StateGraph(JudgmentGraphState)
        builder.add_node("prepare_iteration", self._prepare_iteration)
        builder.add_node("plan_action", self._plan_action)
        builder.add_node("validate_action", self._validate_action)
        builder.add_node("execute_action", self._execute_action)
        builder.add_node("handle_scope", self._handle_scope)
        builder.add_node("evaluate_verdict", self._evaluate_verdict)
        builder.add_edge(START, "prepare_iteration")
        builder.add_conditional_edges(
            "prepare_iteration",
            lambda value: value["route"],
            {"plan": "plan_action", "finish": "evaluate_verdict", "end": END},
        )
        builder.add_edge("plan_action", "validate_action")
        builder.add_conditional_edges(
            "validate_action",
            lambda value: value["route"],
            {
                "execute": "execute_action",
                "scope": "handle_scope",
                "finish": "evaluate_verdict",
                "validate": "validate_action",
                "retry": "prepare_iteration",
            },
        )
        builder.add_conditional_edges(
            "execute_action",
            lambda value: value["route"],
            {"continue": "prepare_iteration", "validate": "validate_action", "retry": "prepare_iteration", "end": END},
        )
        builder.add_conditional_edges(
            "handle_scope",
            lambda value: value["route"],
            {"continue": "prepare_iteration", "validate": "validate_action", "retry": "prepare_iteration", "end": END},
        )
        builder.add_edge("evaluate_verdict", END)
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
                "pending_actions": [],
                "route": "plan",
            },
            config=graph_config,
        )
        return InvestigationState.model_validate(result["investigation"])

    def _prepare_iteration(self, graph_state: JudgmentGraphState) -> JudgmentGraphState:
        state = graph_state["investigation"].model_copy(deep=True)
        if state.finished:
            return {"investigation": state, "action": None, "pending_actions": [], "route": "end"}
        state.budget.iterations_used += 1
        if state.budget.iterations_used > state.budget.max_iterations:
            # Budget exhausted: still generate a report from whatever was queried.
            return {"investigation": state, "action": None, "pending_actions": [], "route": "finish"}
        return {"investigation": state, "action": None, "pending_actions": [], "route": "plan"}

    def _plan_action(self, graph_state: JudgmentGraphState) -> JudgmentGraphState:
        state = graph_state["investigation"].model_copy(deep=True)
        actions = list(self.planner.plan(state))
        if not actions:
            actions = [FinishRequest(objective="模型未产生任何调查动作，结束调查")]
        current = actions[0]
        pending = actions[1:]
        return {"investigation": state, "action": current, "pending_actions": pending, "route": "plan"}

    def _validate_action(self, graph_state: JudgmentGraphState) -> JudgmentGraphState:
        state = graph_state["investigation"].model_copy(deep=True)
        action = graph_state.get("action")
        pending = list(graph_state.get("pending_actions") or [])
        if action is None:
            raise RuntimeError("Planner produced no investigation action")
        try:
            validate_action(
                action, state,
                data_tool_mode=bool(getattr(self.planner, "uses_data_tools", False)),
            )
        except (PolicyError, KeyError) as error:
            self._record_rejected(state, action, str(error))
            return self._next_action(state, pending)
        if isinstance(action, FinishRequest):
            route: Route = "finish"
        elif isinstance(action, ScopeRequest):
            route = "scope"
        else:
            route = "execute"
        return {"investigation": state, "action": action, "pending_actions": pending, "route": route}

    @staticmethod
    def _next_action(state: InvestigationState, pending: list[InvestigationAction]) -> JudgmentGraphState:
        if pending:
            return {
                "investigation": state,
                "action": pending[0],
                "pending_actions": pending[1:],
                "route": "validate",
            }
        return {"investigation": state, "action": None, "pending_actions": [], "route": "retry"}

    def _execute_action(self, graph_state: JudgmentGraphState) -> JudgmentGraphState:
        state = graph_state["investigation"].model_copy(deep=True)
        action = graph_state.get("action")
        pending = list(graph_state.get("pending_actions") or [])
        if not isinstance(action, DataToolRequest):
            raise RuntimeError("Execution node requires a data-tool request")
        call = ToolCall(
            call_id=f"call-{uuid.uuid4().hex[:10]}",
            tool_name=action.tool_name,
            action_type=action.action_type,
            status="success",
            objective=action.objective,
            parameters=action.arguments,
        )
        try:
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
        except (PolicyError, KeyError) as exc:
            call.status, call.error = "denied", str(exc)
        except Exception as exc:
            call.status, call.error = "error", f"{type(exc).__name__}: {exc}"
            if self.data_tool_gateway is not None:
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
        state.budget.tool_calls_used += 1
        state.tool_calls.append(call)
        return self._next_action(state, pending)

    def _handle_scope(self, graph_state: JudgmentGraphState) -> JudgmentGraphState:
        state = graph_state["investigation"].model_copy(deep=True)
        action = graph_state.get("action")
        pending = list(graph_state.get("pending_actions") or [])
        if not isinstance(action, ScopeRequest):
            raise RuntimeError("Scope node requires ScopeRequest")
        approved = state.scope.expansion_policy == "automatic"
        state.scope_expansions.append(ScopeExpansion(
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
        ))
        if not approved and self.scope_approval_mode == "defer":
            return {"investigation": state, "action": None, "pending_actions": pending, "route": "end"}
        self.apply_scope_decision(
            state,
            approved=approved,
            approval_source="policy:auto" if approved else "policy:legacy-denial",
            objective=action.objective,
        )
        return self._next_action(state, pending)

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
                    state.entities.append(Entity(
                        entity_id=entity_id,
                        entity_type="host",
                        attributes={"scope_expansion": expansion.expansion_id},
                    ))
            state.budget.scope_expansions_used += 1
        state.tool_calls.append(ToolCall(
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
        ))
        return state

    def _evaluate_verdict(self, graph_state: JudgmentGraphState) -> JudgmentGraphState:
        state = graph_state["investigation"].model_copy(deep=True)
        if self.report_composer is not None:
            report = self.report_composer.compose(state)
            report_errors = self.report_composer.validate(state, report)
            attempts = 0
            while report_errors and attempts < state.budget.max_verdict_repairs:
                attempts += 1
                report = self.report_composer.repair(state, report, report_errors)
                report_errors = self.report_composer.validate(state, report)
            state.report_validation_errors = list(report_errors)
            state.investigation_report = report
            state.verdict = report.verdict
        state.finished = True
        return {"investigation": state, "action": None, "route": "end"}

    @staticmethod
    def _record_rejected(state: InvestigationState, action: InvestigationAction, error: str) -> None:
        """Record a rejected action: a denied ToolCall plus, for data tools, a
        ToolError trace so the model sees the rejection reason on its next turn."""
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
        if isinstance(action, DataToolRequest):
            from ...contracts import InvestigationToolTrace
            state.tool_ledger.traces.append(InvestigationToolTrace(
                sequence=len(state.tool_ledger.traces) + 1,
                tool_name=action.tool_name,
                arguments=action.arguments,
                result_type="ToolError",
                result={"error_type": "PolicyError", "error_message": error},
                tool_call_id=action.tool_call_id,
                model_message=action.model_message,
            ))
