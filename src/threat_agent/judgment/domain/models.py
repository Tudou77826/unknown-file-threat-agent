from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal, TypeAlias

from pydantic import Field, RootModel

from ...contracts.evidence import Coverage, Entity, Evidence, EvidenceBundle, EvidenceStatus, Scope
from ...contracts import InvestigationReport, InvestigationToolLedger
from ...contracts.investigation import CandidateVerdict, Fact, Finding, Relation, VerdictLevel
from ...shared import StrictModel


class Claim(StrictModel):
    claim_id: str
    claim_type: str
    statement: str
    source_evidence_refs: list[str]
    verification_state: Literal["unverified", "supported", "confirmed", "contradicted"] = "unverified"
    verification_requirements: list[str] = Field(default_factory=list)


class Hypothesis(StrictModel):
    hypothesis_id: str
    hypothesis_type: str
    statement: str
    supporting_refs: list[str] = Field(default_factory=list)
    contradicting_refs: list[str] = Field(default_factory=list)
    missing_evidence_gap_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.2, ge=0, le=1)
    status: Literal["open", "supported", "rejected", "confirmed"] = "open"


class EvidenceGap(StrictModel):
    gap_id: str
    gap_type: str = "generic"
    question: str
    reason: str
    required_evidence_types: list[str]
    requirement_mode: Literal["all", "any"] = "all"
    recommended_tools: list[str] = Field(default_factory=list)
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    required_for_closure: bool = True
    status: Literal[
        "open",
        "querying",
        "evidence_collected",
        "analyzing",
        "resolved",
        "partially_resolved",
        "unresolvable",
    ] = "open"
    resolution: Literal["none", "positive", "negative", "partial", "unresolvable"] = "none"
    resolution_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class AnalysisObligation(StrictModel):
    obligation_id: str
    tool_name: str
    reason: str
    evidence_refs: list[str] = Field(min_length=1)
    gap_ids: list[str] = Field(default_factory=list)
    primary_gap_id: str | None = None
    required_for_closure: bool = True
    status: Literal["pending", "running", "completed", "failed", "unresolvable"] = "pending"
    outcome: Literal["none", "positive", "negative", "partial"] = "none"
    result_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class EvidenceRole(StrictModel):
    role_id: str
    role_type: Literal[
        "identity",
        "execution",
        "provenance",
        "behavior",
        "attribution",
        "impact",
        "scope",
        "counter_evidence",
    ]
    question: str
    hypothesis_refs: list[str] = Field(default_factory=list)
    required_evidence_types: list[str] = Field(default_factory=list)
    requirement_mode: Literal["all", "any"] = "all"
    satisfied_by_refs: list[str] = Field(default_factory=list)
    status: Literal["unsatisfied", "partially_satisfied", "satisfied", "unavailable"] = "unsatisfied"
    required_for_verdict: bool = False


class PlannerDecision(StrictModel):
    decision_id: str
    iteration: int
    decision_type: Literal["investigate", "analyze", "scope", "finish"]
    selected_tool: str | None = None
    target_hypothesis_id: str | None = None
    target_evidence_role_id: str | None = None
    target_gap_id: str | None = None
    decision_summary: str
    candidate_tools: list[str] = Field(default_factory=list)
    activated_scenarios: list[str] = Field(default_factory=list)
    planner_mode: Literal["deterministic", "deepagents", "automatic"]
    repaired: bool = False
    fallback_used: bool = False


class ToolScore(StrictModel):
    iteration: int
    tool_name: str
    score: float
    compatible_gap_ids: list[str] = Field(default_factory=list)
    matching_role_ids: list[str] = Field(default_factory=list)
    components: dict[str, float] = Field(default_factory=dict)
    rationale: list[str] = Field(default_factory=list)


class EvidencePack(StrictModel):
    pack_id: str
    request_call_id: str
    tool_name: str
    target_gap_id: str
    target_role_ids: list[str] = Field(default_factory=list)
    target_hypothesis_ids: list[str] = Field(default_factory=list)
    query_parameters: dict[str, Any] = Field(default_factory=dict)
    requested_host_ids: list[str] = Field(default_factory=list)
    requested_start: datetime | None = None
    requested_end: datetime | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    returned_evidence_types: list[str] = Field(default_factory=list)
    coverage: Coverage
    analysis_obligation_refs: list[str] = Field(default_factory=list)
    outcome: Literal["positive", "negative", "partial", "unavailable", "error"]
    limitations: list[str] = Field(default_factory=list)


class RepairAction(StrictModel):
    repair_id: str
    repair_type: Literal[
        "repair_invalid_action",
        "collect_missing_evidence",
        "use_alternative_source",
        "complete_analyzer_inputs",
        "repair_verdict_support",
        "respect_scope_denial",
        "converge_under_budget",
    ]
    trigger: str
    target_gap_id: str | None = None
    recommended_tools: list[str] = Field(default_factory=list)
    reason_evidence_refs: list[str] = Field(default_factory=list)
    reason: str
    blocking: bool = False
    status: Literal["pending", "applied", "exhausted", "dismissed"] = "pending"
    attempts: int = 0
    max_attempts: int = 1
    limitations: list[str] = Field(default_factory=list)


class ScopeExpansion(StrictModel):
    expansion_id: str
    candidate_host_ids: list[str]
    reason_type: str
    reason_evidence_refs: list[str]
    requested_domains: list[str] = Field(default_factory=list)
    start_time: datetime | None = None
    end_time: datetime | None = None
    approval_status: Literal["pending", "approved", "denied"] = "pending"
    approval_source: str | None = None
    limitations: list[str] = Field(default_factory=list)


class Budget(StrictModel):
    max_iterations: int = 48
    max_tool_calls: int = 60
    iterations_used: int = 0
    tool_calls_used: int = 0
    max_scope_expansions: int = 2
    scope_expansions_used: int = 0
    max_repair_actions: int = 8
    repair_actions_used: int = 0
    max_verdict_repairs: int = 2
    verdict_repairs_used: int = 0


class ToolCall(StrictModel):
    call_id: str
    tool_name: str
    action_type: str
    status: Literal["success", "empty", "partial", "unavailable", "denied", "error"]
    objective: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class EvidenceRequest(StrictModel):
    action_type: Literal["evidence_request"] = "evidence_request"
    tool_name: str = Field(min_length=1)
    objective: str = Field(min_length=10)
    gap_id: str = Field(min_length=1)
    parameters: dict[str, Any] = Field(default_factory=dict)


class AnalysisRequest(StrictModel):
    action_type: Literal["analysis_request"] = "analysis_request"
    tool_name: str = Field(min_length=1)
    objective: str = Field(min_length=10)
    evidence_refs: list[str] = Field(min_length=1)
    parameters: dict[str, Any] = Field(default_factory=dict)


class ScopeRequest(StrictModel):
    action_type: Literal["scope_request"] = "scope_request"
    objective: str = Field(min_length=10)
    requested_host_ids: list[str] = Field(min_length=1)
    reason_evidence_refs: list[str] = Field(min_length=1)
    reason_type: str = "related_host_evidence"
    requested_domains: list[str] = Field(default_factory=lambda: ["process", "file", "network"])
    start_time: datetime | None = None
    end_time: datetime | None = None


class FinishRequest(StrictModel):
    action_type: Literal["finish_request"] = "finish_request"
    objective: str = Field(min_length=10)
    resolved_gap_ids: list[str] = Field(default_factory=list)
    unresolved_gap_ids: list[str] = Field(default_factory=list)


class ScenarioActivationRequest(StrictModel):
    action_type: Literal["scenario_activation"] = "scenario_activation"
    scenario: str = Field(min_length=1)
    objective: str = Field(min_length=10)
    reason_refs: list[str] = Field(min_length=1)


class DataToolRequest(StrictModel):
    action_type: Literal["data_tool_request"] = "data_tool_request"
    tool_name: Literal[
        "query_activities", "explore_entity", "get_raw_records", "calculate_activity_metrics"
    ]
    objective: str = Field(min_length=10)
    arguments: dict[str, Any] = Field(default_factory=dict)
    tool_call_id: str | None = None
    model_message: dict[str, Any] = Field(default_factory=dict)


InvestigationAction: TypeAlias = Annotated[
    EvidenceRequest
    | AnalysisRequest
    | DataToolRequest
    | ScopeRequest
    | FinishRequest
    | ScenarioActivationRequest,
    Field(discriminator="action_type"),
]


class InvestigationActionResponse(RootModel[InvestigationAction]):
    """Concrete response model required by Deep Agents/LangChain ToolStrategy."""



class FactFindingBundle(StrictModel):
    facts: list[Fact] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class InvestigationState(StrictModel):
    case_id: str
    raw_input: dict[str, Any]
    entities: list[Entity]
    claims: list[Claim] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    facts: list[Fact] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    evidence_roles: list[EvidenceRole] = Field(default_factory=list)
    evidence_gaps: list[EvidenceGap] = Field(default_factory=list)
    analysis_obligations: list[AnalysisObligation] = Field(default_factory=list)
    coverage: dict[str, Coverage] = Field(default_factory=dict)
    scope: Scope
    scope_expansions: list[ScopeExpansion] = Field(default_factory=list)
    budget: Budget = Field(default_factory=Budget)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    planner_decisions: list[PlannerDecision] = Field(default_factory=list)
    tool_scores: list[ToolScore] = Field(default_factory=list)
    evidence_packs: list[EvidencePack] = Field(default_factory=list)
    repair_actions: list[RepairAction] = Field(default_factory=list)
    active_scenarios: list[str] = Field(default_factory=lambda: ["c2"])
    verdict_validation_errors: list[str] = Field(default_factory=list)
    verdict: CandidateVerdict | None = None
    tool_ledger: InvestigationToolLedger = Field(default_factory=InvestigationToolLedger)
    investigation_report: InvestigationReport | None = None
    report_validation_errors: list[str] = Field(default_factory=list)
    finished: bool = False
