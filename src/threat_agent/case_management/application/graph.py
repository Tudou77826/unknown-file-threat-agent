from __future__ import annotations

from typing import Any, Literal, Protocol, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from ...contracts import InvestigationReport, JudgmentResult, ResponsePlan
from ...shared.execution import ExecutionContext, bind_execution_context
from .contract_builders import build_judgment_result
from ...judgment.domain.models import InvestigationState
from ...response_advisory import ResponseGraph


class CaseGraphState(TypedDict, total=False):
    tenant_id: str
    run_id: str
    lifecycle_status: str
    investigation: InvestigationState
    judgment_result: JudgmentResult | None
    investigation_report: InvestigationReport | None
    response_plan: ResponsePlan | None
    approval_status: str | None
    route: Literal["judged", "response", "response_approval", "complete"]


class JudgmentStagePort(Protocol):
    """The framework-neutral subgraph contract consumed by case governance."""

    compiled: Any


class CaseGraph:
    """Parent graph for durable case lifecycle orchestration.

    The investigation boundary is single-host: there is no scope-approval
    branch. Cross-host leads surface as report limitations only. Response-plan
    approval is unaffected.
    """

    def __init__(
        self,
        judgment_graph: JudgmentStagePort,
        *,
        checkpointer: Any,
        response_graph: ResponseGraph | None = None,
        recursion_limit: int = 1000,
    ):
        self.judgment_graph = judgment_graph
        self.response_graph = response_graph
        self.recursion_limit = recursion_limit
        builder = StateGraph(CaseGraphState)
        builder.add_node("run_judgment", self.judgment_graph.compiled)
        builder.add_node("route_after_judgment", self._route_after_judgment)
        builder.add_node("publish_judgment", self._publish_judgment)
        if self.response_graph is not None:
            builder.add_node("run_response_advisory", self.response_graph.compiled)
        else:
            builder.add_node("run_response_advisory", self._skip_response_advisory)
        builder.add_node("route_after_response", self._route_after_response)
        builder.add_node("approve_response", self._approve_response)
        builder.add_edge(START, "run_judgment")
        builder.add_edge("run_judgment", "route_after_judgment")
        builder.add_conditional_edges(
            "route_after_judgment",
            lambda value: value["route"],
            {"judged": "publish_judgment"},
        )
        builder.add_conditional_edges(
            "publish_judgment",
            lambda value: value["route"],
            {"response": "run_response_advisory", "complete": END},
        )
        builder.add_edge("run_response_advisory", "route_after_response")
        builder.add_conditional_edges(
            "route_after_response",
            lambda value: value["route"],
            {"response_approval": "approve_response", "complete": END},
        )
        builder.add_edge("approve_response", END)
        self.compiled = builder.compile(checkpointer=checkpointer)

    @staticmethod
    def thread_id(tenant_id: str, case_id: str, run_id: str) -> str:
        return f"{tenant_id}/{case_id}/{run_id}"

    def start(
        self,
        state: InvestigationState,
        *,
        tenant_id: str = "default",
        run_id: str = "primary",
    ) -> dict[str, Any]:
        config = {
            "configurable": {
                "thread_id": self.thread_id(tenant_id, state.case_id, run_id),
            },
            "recursion_limit": self.recursion_limit,
        }
        # 授权执行上下文在框架入口一次绑定、全程继承（设计 §7 授权继承）：
        # 研判循环、知识能力层与处置子图都在这条链上读取身份，业务代码不传递。
        with bind_execution_context(
            ExecutionContext(
                tenant_id=tenant_id,
                case_id=state.case_id,
                actor_id=f"case-graph/{run_id}",
                run_id=run_id,
            )
        ):
            return self.compiled.invoke(
                {
                    "tenant_id": tenant_id,
                    "run_id": run_id,
                    "lifecycle_status": "investigating",
                    "investigation": state.model_copy(deep=True),
                    "judgment_result": None,
                    "investigation_report": None,
                    "response_plan": None,
                    "approval_status": None,
                },
                config=config,
            )

    def resume_response(
        self,
        *,
        tenant_id: str,
        case_id: str,
        run_id: str = "primary",
        approved: bool,
        approved_by: str,
        comment: str | None = None,
        edited_plan: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        config = {
            "configurable": {
                "thread_id": self.thread_id(tenant_id, case_id, run_id),
            },
            "recursion_limit": self.recursion_limit,
        }
        value: dict[str, Any] = {
            "approved": approved,
            "approved_by": approved_by,
            # v2 optional fields (Feature 17): absent values stay v1-compatible.
            "comment": comment,
            "edited_plan": edited_plan,
        }
        with bind_execution_context(
            ExecutionContext(
                tenant_id=tenant_id,
                case_id=case_id,
                actor_id=f"case-graph/{run_id}",
                run_id=run_id,
            )
        ):
            return self.compiled.invoke(Command(resume=value), config=config)

    def state_history(
        self, *, tenant_id: str, case_id: str, run_id: str = "primary"
    ) -> list[Any]:
        """Checkpoint snapshots for the run, newest first (read-only: no
        execution context is bound because nothing executes)."""

        config = {"configurable": {"thread_id": self.thread_id(tenant_id, case_id, run_id)}}
        return list(self.compiled.get_state_history(config))

    def resume_from(
        self,
        *,
        tenant_id: str,
        case_id: str,
        run_id: str = "primary",
        checkpoint_id: str,
        value: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Re-execute from a past checkpoint (debug time travel).

        ``value=None`` replays the graph from the checkpoint; a dict value
        resumes a pending interrupt. Goes through the same entry binding as
        every other execution path — never around it.
        """

        config = {
            "configurable": {
                "thread_id": self.thread_id(tenant_id, case_id, run_id),
                "checkpoint_id": checkpoint_id,
            },
            "recursion_limit": self.recursion_limit,
        }
        with bind_execution_context(
            ExecutionContext(
                tenant_id=tenant_id,
                case_id=case_id,
                actor_id=f"case-graph/{run_id}",
                run_id=run_id,
            )
        ):
            payload = Command(resume=value) if value is not None else None
            return self.compiled.invoke(payload, config=config)

    @staticmethod
    def _route_after_judgment(case_state: CaseGraphState) -> CaseGraphState:
        return {"lifecycle_status": "judged", "route": "judged"}

    def _publish_judgment(self, case_state: CaseGraphState) -> CaseGraphState:
        state = case_state["investigation"]
        result = build_judgment_result(
            state,
            tenant_id=case_state["tenant_id"],
            source_identity="case-graph/judgment",
        )
        return {
            "judgment_result": result,
            "investigation_report": state.investigation_report,
            "lifecycle_status": "judged",
            "route": "response" if self.response_graph is not None else "complete",
        }

    @staticmethod
    def _skip_response_advisory(case_state: CaseGraphState) -> CaseGraphState:
        return {"lifecycle_status": "judged", "route": "complete"}

    def _route_after_response(self, case_state: CaseGraphState) -> CaseGraphState:
        plan = case_state.get("response_plan")
        if plan is None:
            return {"lifecycle_status": "judged", "route": "complete"}
        approval_required = plan.status == "approval_required"
        return {
            "lifecycle_status": "awaiting_response_approval" if approval_required else "advised",
            "route": "response_approval" if approval_required else "complete",
        }

    def _approve_response(self, case_state: CaseGraphState) -> CaseGraphState:
        plan = case_state.get("response_plan")
        if plan is None:
            raise RuntimeError("Response approval requires a response plan")
        decision = interrupt(
            {
                "kind": "response_approval",
                "case_id": plan.case_id,
                "response_plan": plan.model_dump(mode="json"),
            }
        )
        if not isinstance(decision, dict) or not isinstance(decision.get("approved"), bool):
            raise ValueError("Response approval resume value must contain boolean approved")
        approved_by = str(decision.get("approved_by") or "unknown")
        comment = decision.get("comment")
        edited_plan = decision.get("edited_plan")
        effective_plan = plan
        if edited_plan:
            # An editor's plan must satisfy the same contract as the planner's
            # own output; invalid edits fail loudly instead of silently passing.
            effective_plan = ResponsePlan.model_validate(edited_plan)
        status_suffix = f"comment:{comment}" if comment else ""
        return {
            "response_plan": effective_plan,
            "approval_status": " ".join(
                part
                for part in (
                    (
                        f"response_approved_by:{approved_by}"
                        if decision["approved"]
                        else f"response_denied_by:{approved_by}"
                    ),
                    f"edited_by:{approved_by}" if edited_plan else "",
                    status_suffix,
                )
                if part
            ),
            "lifecycle_status": "advised",
            "route": "complete",
        }
