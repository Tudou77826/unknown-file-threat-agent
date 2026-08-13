from __future__ import annotations

from typing import Any

from pydantic import Field

from .common import ContractModel
from .evidence import Coverage
from .investigation import JudgmentResult
from .response import ResponsePlan


class CaseReadModel(ContractModel):
    lifecycle_status: str
    judgment: JudgmentResult | None = None
    response_plan: ResponsePlan | None = None
    entities: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    attack_path: list[dict[str, Any]] = Field(default_factory=list)
    facts: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    evidence_roles: list[dict[str, Any]] = Field(default_factory=list)
    interpretations: list[dict[str, Any]] = Field(default_factory=list)
    coverage: dict[str, Coverage] = Field(default_factory=dict)
    analysis_obligations: list[dict[str, Any]] = Field(default_factory=list)
    evidence_gaps: list[dict[str, Any]] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    planner_decisions: list[dict[str, Any]] = Field(default_factory=list)
    tool_scores: list[dict[str, Any]] = Field(default_factory=list)
    evidence_packs: list[dict[str, Any]] = Field(default_factory=list)
    repair_actions: list[dict[str, Any]] = Field(default_factory=list)
    active_scenarios: list[str] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)
    scope_expansions: list[dict[str, Any]] = Field(default_factory=list)
    verdict_validation_errors: list[str] = Field(default_factory=list)
    analysis_notes: list[str] = Field(default_factory=list)
    investigation_timeline: list[dict[str, Any]] = Field(default_factory=list)
    approval_status: str | None = None
    limitations: list[str] = Field(default_factory=list)
