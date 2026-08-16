from __future__ import annotations

import uuid
from typing import Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph

from ..domain.models import (
    DataToolRequest,
    FinishRequest,
    InvestigationAction,
    InvestigationState,
    ToolCall,
)
from .boundary import BoundaryViolationError
from .policy import PolicyError, validate_action


Route = Literal["plan", "execute", "finish", "retry", "continue", "validate", "end"]


class JudgmentGraphState(TypedDict, total=False):
    investigation: InvestigationState
    action: InvestigationAction | None
    pending_actions: list[InvestigationAction]
    route: Route


class JudgmentGraph:
    """LangGraph runtime for the data-tool driven AI judgment loop.

    The investigation boundary is single-host: the tenant and run identity are
    server-side constructor facts (injected by bootstrap), never taken from the
    alert payload, and every data tool call flows through the gateway's
    ``InvestigationBoundaryPort``.
    """

    def __init__(
        self,
        planner,
        *,
        checkpointer: Any = None,
        tenant_id: str = "default",
        run_id: str = "primary",
        data_tool_gateway=None,
        report_composer=None,
        report_validator=None,
        report_coordinator=None,
        fallback_builder=None,
        report_publisher=None,
        recursion_limit: int = 1000,
    ):
        self.planner = planner
        self.tenant_id = tenant_id
        self.run_id = run_id
        self.data_tool_gateway = data_tool_gateway
        self.report_composer = report_composer
        self.report_validator = report_validator
        self.report_coordinator = report_coordinator
        self.fallback_builder = fallback_builder
        self.report_publisher = report_publisher
        self.recursion_limit = recursion_limit
        builder = StateGraph(JudgmentGraphState)
        builder.add_node("prepare_iteration", self._prepare_iteration)
        builder.add_node("plan_action", self._plan_action)
        builder.add_node("validate_action", self._validate_action)
        builder.add_node("execute_action", self._execute_action)
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
        route: Route = "finish" if isinstance(action, FinishRequest) else "execute"
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
        if state.budget.tool_calls_used >= state.budget.max_tool_calls:
            self._record_rejected(state, action, "Tool-call budget exhausted")
            return self._next_action(state, pending)
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
            # Tenant and run identity are server-side facts; the alert payload
            # (raw_input) must never override them.
            self.data_tool_gateway.invoke(
                action.tool_name,
                action.arguments,
                ToolRuntimeContext(
                    tenant_id=self.tenant_id,
                    case_id=state.case_id,
                    run_id=self.run_id,
                    scope=state.scope,
                ),
                state.tool_ledger,
                tool_call_id=action.tool_call_id,
                model_message=action.model_message,
            )
        except BoundaryViolationError as denial:
            # Structured rejection fed back to the model: a boundary denial is
            # never disguised as an empty query result.
            call.status, call.error = "denied", f"{denial.code}: {denial.message}"
            from ...contracts import InvestigationToolTrace
            state.tool_ledger.traces.append(InvestigationToolTrace(
                sequence=len(state.tool_ledger.traces) + 1,
                tool_name=action.tool_name,
                arguments=action.arguments,
                result_type="ToolError",
                result={
                    "error_type": "BoundaryDenied",
                    "error_code": denial.code,
                    "error_message": denial.message,
                },
                tool_call_id=action.tool_call_id,
                model_message=action.model_message,
            ))
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

    def _evaluate_verdict(self, graph_state: JudgmentGraphState) -> JudgmentGraphState:
        state = graph_state["investigation"].model_copy(deep=True)
        if self.report_composer is not None:
            # Publish first, expose second: state.investigation_report and
            # state.verdict are only written after a report (grounded or
            # fallback) has actually been published.
            report = self._publish_report(state)
            state.investigation_report = report
            state.verdict = report.verdict
        state.finished = True
        return {"investigation": state, "action": None, "route": "end"}

    def _publish_report(self, state: InvestigationState):
        """Orchestrate the report stages; implement none of them inline.

        Stages per Feature 14: draft -> grounding validation -> constrained
        rejudgment within budget -> cited-evidence gate -> final consistency ->
        publish grounded or fallback. Reference filtering, evidence capability
        math and fallback field assembly live in the collaborators.
        """
        from .evidence_gate import gate_verdict
        from .report_repair import ReportRepairCoordinator
        from .report_validation import ReportGroundingValidator
        from .reporting import DeterministicFallbackBuilder, ReportPublisher

        composer = self.report_composer
        validator = self.report_validator or ReportGroundingValidator()
        coordinator = self.report_coordinator or ReportRepairCoordinator(
            composer, validator
        )
        fallback_builder = self.fallback_builder or DeterministicFallbackBuilder()
        publisher = self.report_publisher or ReportPublisher(
            tenant_id=self.tenant_id,
            run_id=self.run_id,
            model_name=str(getattr(composer, "model_name", "unknown")),
        )

        draft = composer.compose_draft(state)
        outcome = coordinator.evaluate(
            state, draft, max_rejudgments=state.budget.max_report_rejudgments
        )
        draft = outcome.draft
        state.budget.report_rejudgments_used = outcome.rejudgments_used

        issues = outcome.issues
        if not issues:
            gated_verdict = gate_verdict(state, draft.verdict)
            draft = draft.model_copy(update={"verdict": gated_verdict})
            # Final consistency after the deterministic gate (downgrade adds a
            # limitation; grounding must still hold on the gated draft).
            issues = validator.validate(state, draft)

        if issues:
            state.report_validation_errors = [
                f"{issue.code}@{issue.location}" for issue in issues
            ]
            fallback_draft = fallback_builder.build_draft(state, issues)
            return publisher.publish(
                state, fallback_draft, publication_status="fallback"
            )

        state.report_validation_errors = []
        return publisher.publish(state, draft, publication_status="grounded")

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
