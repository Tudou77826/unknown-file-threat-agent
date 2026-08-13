from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from ..shared import StrictModel
from .common import ContractModel
from .investigation import CandidateVerdict
from .response import ResponsePlan


class ReportStatement(StrictModel):
    statement_id: str = Field(min_length=1)
    text: str = Field(min_length=1)
    supporting_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class InvestigationReport(ContractModel):
    report_id: str = Field(min_length=1)
    report_version: int = Field(ge=1)
    run_id: str = Field(min_length=1)
    verdict: CandidateVerdict
    threat_scenarios: list[str] = Field(default_factory=list)
    executive_summary: str = Field(min_length=1)
    current_situation: list[ReportStatement] = Field(default_factory=list)
    affected_scope: list[ReportStatement] = Field(default_factory=list)
    key_evidence: list[ReportStatement] = Field(default_factory=list)
    supporting_evidence_refs: list[str] = Field(default_factory=list)
    counter_evidence: list[ReportStatement] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    query_boundary_refs: list[str] = Field(default_factory=list)
    asserted_host_refs: list[str] = Field(default_factory=list)
    asserted_start: datetime | None = None
    asserted_end: datetime | None = None
    confirmed_relation_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    producer: str = Field(min_length=1)
    model_version: str = Field(min_length=1)
    prompt_version: str = Field(min_length=1)


class InvestigationRun(ContractModel):
    run_id: str = Field(min_length=1)
    status: Literal["queued", "running", "completed", "failed"]
    stage: str = Field(min_length=1)
    graph_thread_id: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    report_id: str | None = None
    response_plan_id: str | None = None
    error_type: str | None = None


class OperationalEvent(ContractModel):
    run_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    sequence: int = Field(ge=1)
    event_type: Literal["graph", "model", "tool", "validation", "run", "error"]
    stage: str = Field(min_length=1)
    duration_ms: float | None = Field(default=None, ge=0)
    token_usage: dict[str, int] = Field(default_factory=dict)
    retry_count: int = Field(default=0, ge=0)
    details: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str = Field(min_length=1)


class AuditEvent(ContractModel):
    run_id: str = Field(min_length=1)
    audit_id: str = Field(min_length=1)
    sequence: int = Field(ge=1)
    action: str = Field(min_length=1)
    resource_type: str = Field(min_length=1)
    resource_ref: str = Field(min_length=1)
    scope_snapshot: dict[str, Any] = Field(default_factory=dict)
    input_refs: list[str] = Field(default_factory=list)
    result_summary: str = Field(min_length=1)
    correlation_id: str = Field(min_length=1)


class InvestigationCreateRequest(StrictModel):
    """Minimal request for a reference-data investigation run."""

    reference_dataset_id: str = Field(min_length=1)
    profile_id: str = Field(min_length=1)


class InvestigationRunReadModel(StrictModel):
    run: InvestigationRun
    reference_dataset_id: str
    profile_id: str
    events: list[OperationalEvent] = Field(default_factory=list)
    investigation_report: InvestigationReport | None = None
    response_plan: ResponsePlan | None = None
