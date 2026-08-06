from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, RootModel


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class EvidenceStatus(str, Enum):
    AVAILABLE = "available"
    EMPTY = "empty"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class VerdictLevel(str, Enum):
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    LIKELY_MALICIOUS = "likely_malicious"
    SUSPICIOUS = "suspicious"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    LIKELY_BENIGN = "likely_benign"
    BENIGN = "benign"


class Entity(StrictModel):
    entity_id: str
    entity_type: Literal[
        "host", "file", "process", "network_endpoint", "persistence", "user", "container",
        "session", "archive", "package", "service", "directory", "data_object",
        "credential",
    ]
    attributes: dict[str, Any] = Field(default_factory=dict)


class Evidence(StrictModel):
    evidence_id: str
    evidence_type: str
    domain: str
    source_system: str
    observed_at: datetime | None = None
    subject_refs: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    status: EvidenceStatus = EvidenceStatus.AVAILABLE
    limitations: list[str] = Field(default_factory=list)
    raw_reference: str | None = None


class Claim(StrictModel):
    claim_id: str
    claim_type: str
    statement: str
    source_evidence_refs: list[str]
    verification_state: Literal["unverified", "supported", "confirmed", "contradicted"] = "unverified"
    verification_requirements: list[str] = Field(default_factory=list)


class Fact(StrictModel):
    fact_id: str
    fact_type: str
    statement: str
    subject_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str]
    observed_at: datetime | None = None
    verification_method: str


class Finding(StrictModel):
    finding_id: str
    finding_type: str
    statement: str
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    subject_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str]
    supporting_fact_refs: list[str] = Field(default_factory=list)
    analyzer: str
    analyzer_version: str = "1.0"
    confidence: float = Field(ge=0, le=1)
    limitations: list[str] = Field(default_factory=list)


class Relation(StrictModel):
    relation_id: str
    relation_type: str
    source_entity_ref: str
    target_entity_ref: str
    evidence_refs: list[str]
    confidence: Literal["confirmed", "supported", "candidate"] = "supported"
    observed_at: datetime | None = None
    limitations: list[str] = Field(default_factory=list)


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


class Coverage(StrictModel):
    domain: str
    status: EvidenceStatus
    host_id: str | None = None
    source_system: str | None = None
    completeness: Literal["complete", "partial", "unknown", "unavailable"] = "unknown"
    requested_start: datetime | None = None
    requested_end: datetime | None = None
    available_start: datetime | None = None
    available_end: datetime | None = None
    result_start: datetime | None = None
    result_end: datetime | None = None
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


class Interpretation(StrictModel):
    interpretation_id: str
    interpretation_type: str
    statement: str
    supporting_fact_refs: list[str] = Field(default_factory=list)
    supporting_finding_refs: list[str] = Field(default_factory=list)
    contradicting_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    status: Literal["candidate", "validated", "rejected"] = "candidate"
    model: str


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
    created_interpretation_id: str | None = None
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


class Scope(StrictModel):
    host_ids: list[str]
    container_ids: list[str] = Field(default_factory=list)
    entity_ids: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=lambda: ["process", "file", "network", "persistence", "reputation"])
    start_time: datetime | None = None
    end_time: datetime | None = None
    expansion_policy: Literal["deny", "approval_required", "automatic"] = "approval_required"


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


InvestigationAction: TypeAlias = Annotated[
    EvidenceRequest | AnalysisRequest | ScopeRequest | FinishRequest,
    Field(discriminator="action_type"),
]


class InvestigationActionResponse(RootModel[InvestigationAction]):
    """Concrete response model required by Deep Agents/LangChain ToolStrategy."""



class EvidenceBundle(StrictModel):
    status: EvidenceStatus
    evidence: list[Evidence] = Field(default_factory=list)
    coverage: Coverage
    limitations: list[str] = Field(default_factory=list)


class FactFindingBundle(StrictModel):
    facts: list[Fact] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class CandidateVerdict(StrictModel):
    level: VerdictLevel
    threat_type: Literal["backdoor_c2", "data_exfiltration", "ransomware", "other", "unknown"]
    summary: str
    supporting_refs: list[str] = Field(default_factory=list)
    contradicting_refs: list[str] = Field(default_factory=list)
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
    interpretations: list[Interpretation] = Field(default_factory=list)
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
    finished: bool = False
