from __future__ import annotations

from typing import Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from ...contracts import JudgmentResult, ResponsePlan
from .contract_builders import build_judgment_result
from ...judgment import JudgmentGraph
from ...judgment.domain.models import InvestigationState
from ...response_advisory import ResponseGraph


class CaseGraphState(TypedDict, total=False):
    tenant_id: str
    run_id: str
    lifecycle_status: str
    investigation: InvestigationState
    judgment_result: JudgmentResult | None
    response_plan: ResponsePlan | None
    approval_status: str | None
    route: Literal["scope_approval", "judged", "response", "response_approval", "complete"]


class CaseGraph:
    """Parent graph for durable case lifecycle orchestration."""

    def __init__(
        self,
        judgment_graph: JudgmentGraph,
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
        builder.add_node("approve_scope", self._approve_scope)
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
            {"scope_approval": "approve_scope", "judged": "publish_judgment"},
        )
        builder.add_edge("approve_scope", "run_judgment")
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
        return self.compiled.invoke(
            {
                "tenant_id": tenant_id,
                "run_id": run_id,
                "lifecycle_status": "investigating",
                "investigation": state.model_copy(deep=True),
                "judgment_result": None,
                "response_plan": None,
                "approval_status": None,
            },
            config=config,
        )

    def resume_scope(
        self,
        *,
        tenant_id: str,
        case_id: str,
        run_id: str = "primary",
        approved: bool,
        approved_by: str,
    ) -> dict[str, Any]:
        config = {
            "configurable": {
                "thread_id": self.thread_id(tenant_id, case_id, run_id),
            },
            "recursion_limit": self.recursion_limit,
        }
        return self.compiled.invoke(
            Command(resume={"approved": approved, "approved_by": approved_by}),
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
    ) -> dict[str, Any]:
        config = {
            "configurable": {
                "thread_id": self.thread_id(tenant_id, case_id, run_id),
            },
            "recursion_limit": self.recursion_limit,
        }
        return self.compiled.invoke(
            Command(resume={"approved": approved, "approved_by": approved_by}),
            config=config,
        )

    def _route_after_judgment(self, case_state: CaseGraphState) -> CaseGraphState:
        result = case_state["investigation"]
        pending = any(item.approval_status == "pending" for item in result.scope_expansions)
        return {
            "lifecycle_status": "awaiting_scope_approval" if pending else "judged",
            "route": "scope_approval" if pending else "judged",
        }

    def _approve_scope(self, case_state: CaseGraphState) -> CaseGraphState:
        state = case_state["investigation"].model_copy(deep=True)
        expansion = next(
            item for item in reversed(state.scope_expansions) if item.approval_status == "pending"
        )
        decision = interrupt(
            {
                "kind": "scope_approval",
                "case_id": state.case_id,
                "expansion_id": expansion.expansion_id,
                "candidate_host_ids": expansion.candidate_host_ids,
                "reason_type": expansion.reason_type,
                "reason_evidence_refs": expansion.reason_evidence_refs,
            }
        )
        if not isinstance(decision, dict) or not isinstance(decision.get("approved"), bool):
            raise ValueError("Scope approval resume value must contain boolean approved")
        approved_by = str(decision.get("approved_by") or "unknown")
        self.judgment_graph.apply_scope_decision(
            state,
            approved=decision["approved"],
            approval_source=f"human:{approved_by}",
        )
        return {
            "investigation": state,
            "approval_status": "approved" if decision["approved"] else "denied",
            "lifecycle_status": "investigating",
        }

    def _publish_judgment(self, case_state: CaseGraphState) -> CaseGraphState:
        state = case_state["investigation"]
        result = build_judgment_result(
            state,
            tenant_id=case_state["tenant_id"],
            source_identity="case-graph/judgment",
        )
        return {
            "judgment_result": result,
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
        return {
            "approval_status": (
                f"response_approved_by:{approved_by}"
                if decision["approved"]
                else f"response_denied_by:{approved_by}"
            ),
            "lifecycle_status": "advised",
            "route": "complete",
        }
