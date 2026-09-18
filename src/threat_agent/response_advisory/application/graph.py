from __future__ import annotations

from typing import Literal, TypedDict

from langgraph.graph import END, START, StateGraph

from ...contracts import (
    JudgmentResult,
    KnowledgeConsultation,
    KnowledgeConsultationContext,
    KnowledgeConsultationResult,
    ResponseContext,
    ResponsePlan,
)
from ...knowledge import NullKnowledgeSupplier, SecurityKnowledgeService
from ..adapters import NullResponseContextProvider
from ..domain.models import ResponseProposal
from ..ports import ResponseContextPort
from .planner import ResponsePlanner
from ..domain.policy import validate_response_proposal


class ResponseGraphState(TypedDict, total=False):
    judgment_result: JudgmentResult
    knowledge_result: KnowledgeConsultationResult | None
    response_context: ResponseContext
    proposal: ResponseProposal | None
    validation_errors: list[str]
    iterations: int
    max_iterations: int
    response_plan: ResponsePlan | None
    route: Literal["repair", "finalize", "end"]


class ResponseGraph:
    def __init__(
        self,
        planner: ResponsePlanner,
        *,
        knowledge_service: SecurityKnowledgeService | None = None,
        response_context_port: ResponseContextPort | None = None,
        max_iterations: int = 3,
        recursion_limit: int = 50,
    ):
        self.planner = planner
        # 未配置部署默认走 Null 供应方：处置知识固定节点仍执行并显式 not_configured
        self.knowledge_service = knowledge_service or SecurityKnowledgeService(
            NullKnowledgeSupplier()
        )
        self.response_context_port = response_context_port or NullResponseContextProvider()
        self.max_iterations = max_iterations
        self.recursion_limit = recursion_limit
        builder = StateGraph(ResponseGraphState)
        builder.add_node("initialize_response", self._initialize_response)
        builder.add_node("load_response_context", self._load_response_context)
        builder.add_node("propose_actions", self._propose_actions)
        builder.add_node("validate_plan", self._validate_plan)
        builder.add_node("finalize_plan", self._finalize_plan)
        builder.add_edge(START, "initialize_response")
        builder.add_edge("initialize_response", "load_response_context")
        builder.add_edge("load_response_context", "propose_actions")
        builder.add_edge("propose_actions", "validate_plan")
        builder.add_conditional_edges(
            "validate_plan",
            lambda value: value["route"],
            {"repair": "propose_actions", "finalize": "finalize_plan"},
        )
        builder.add_edge("finalize_plan", END)
        self.compiled = builder.compile()

    def run(self, judgment: JudgmentResult) -> ResponsePlan:
        result = self.compiled.invoke(
            {
                "judgment_result": judgment,
                "knowledge_result": None,
                "response_context": self.response_context_port.load(judgment),
                "proposal": None,
                "validation_errors": [],
                "iterations": 0,
                "max_iterations": self.max_iterations,
                "response_plan": None,
                "route": "repair",
            },
            config={"recursion_limit": self.recursion_limit},
        )
        return ResponsePlan.model_validate(result["response_plan"])

    def _initialize_response(self, state: ResponseGraphState) -> ResponseGraphState:
        return {
            "knowledge_result": state.get("knowledge_result"),
            "proposal": state.get("proposal"),
            "validation_errors": list(state.get("validation_errors") or []),
            "iterations": int(state.get("iterations", 0)),
            "max_iterations": int(state.get("max_iterations", self.max_iterations)),
            "response_plan": state.get("response_plan"),
            "route": "repair",
        }

    def _load_response_context(self, state: ResponseGraphState) -> ResponseGraphState:
        """生成处置建议前的固定知识节点：经能力层场景服务检索，失败不阻断。"""

        judgment = state["judgment_result"]
        response_context = self.response_context_port.load(judgment)
        request = KnowledgeConsultation(
            scene="response_advisory",
            intent="response_policy_reference",
            context=KnowledgeConsultationContext(
                verdict_summary=(
                    f"{judgment.verdict.threat_type}: {judgment.verdict.summary}"
                ),
                asset_constraints=self._asset_constraints(response_context),
            ),
        )
        try:
            knowledge = self.knowledge_service.consult_response(request)
        except Exception as error:  # noqa: BLE001 — 知识失败不阻断处置主流程
            knowledge = KnowledgeConsultationResult(
                tenant_id=judgment.tenant_id,
                case_id=judgment.case_id,
                source_identity="response-graph/degraded",
                consultation_id="kcon-response-failed",
                query_id="kquery-response-failed",
                scene="response_advisory",
                intent="response_policy_reference",
                status="error",
                limitations=[f"处置知识检索执行失败：{type(error).__name__}: {error}"],
            )
        return {
            "knowledge_result": knowledge,
            "response_context": response_context,
        }

    @staticmethod
    def _asset_constraints(response_context: ResponseContext | None) -> list[str]:
        if response_context is None:
            return []
        constraints: list[str] = []
        for key, value in (response_context.asset_context or {}).items():
            if isinstance(value, (str, int, float, bool)):
                constraints.append(f"{key}={value}")
        return constraints[:8]

    def _propose_actions(self, state: ResponseGraphState) -> ResponseGraphState:
        proposal = self.planner.propose(
            state["judgment_result"],
            state.get("knowledge_result"),
            list(state.get("validation_errors") or []),
            state.get("response_context"),
        )
        return {"proposal": proposal, "iterations": int(state.get("iterations", 0)) + 1}

    def _validate_plan(self, state: ResponseGraphState) -> ResponseGraphState:
        proposal = state.get("proposal")
        if proposal is None:
            errors = ["Response planner returned no proposal"]
        else:
            errors = validate_response_proposal(state["judgment_result"], proposal)
        if errors and state["iterations"] < state["max_iterations"]:
            return {"validation_errors": errors, "route": "repair"}
        return {"validation_errors": errors, "route": "finalize"}

    def _finalize_plan(self, state: ResponseGraphState) -> ResponseGraphState:
        judgment = state["judgment_result"]
        proposal = state.get("proposal") or ResponseProposal()
        errors = list(state.get("validation_errors") or [])
        actions = [] if errors else proposal.actions
        missing_context = list(proposal.missing_context)
        context = state.get("response_context")
        if context is not None:
            missing_context.extend(context.missing_context)
        limitations = list(errors)
        if errors:
            missing_context.append("A policy-valid response plan could not be produced")
            status = "insufficient_context"
        elif any(action.approval_class != "none" for action in actions):
            status = "approval_required"
        else:
            status = "recommended"
        plan = ResponsePlan(
            tenant_id=judgment.tenant_id,
            case_id=judgment.case_id,
            source_identity="response-advisory-graph",
            judgment_schema_version=judgment.schema_version,
            status=status,
            actions=actions,
            missing_context=list(dict.fromkeys(missing_context)),
            residual_risk=proposal.residual_risk,
            limitations=limitations,
        )
        return {"response_plan": plan, "route": "end"}
