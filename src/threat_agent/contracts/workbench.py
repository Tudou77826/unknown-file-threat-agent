"""Workbench contracts (Feature 17): run execution exchange, trajectory,
approval and debug read models. UI-shaped read models are contracts so the
presentation layer keeps consuming stable types only."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from ..shared import StrictModel
from .operations import InvestigationRun

RunControlAction = Literal["start", "replay", "resume"]

RunSource = Literal["reference_dataset", "alert_json"]

ApprovalDecisionKind = Literal["accept", "edit", "respond", "ignore"]


class RunExecutionRequest(StrictModel):
    """What the run service asks of the execution port. Identity is
    server-side: the port never learns identity from payloads."""

    tenant_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    source: RunSource = "reference_dataset"
    dataset_id: str = ""
    profile_id: str = ""
    alert: dict[str, Any] = Field(default_factory=dict)


class RunExecutionOutcome(StrictModel):
    """Generic execution产物: the run service persists artifacts verbatim and
    stays decoupled from demo-specific read models."""

    artifacts: dict[str, dict[str, Any]] = Field(default_factory=dict)
    report_id: str | None = None
    response_plan_id: str | None = None
    result_summary: str = ""
    pending_approval: bool = False


class RunSummary(StrictModel):
    run: InvestigationRun
    dataset_id: str = ""
    profile_id: str = ""


class TrajectoryEntry(StrictModel):
    event_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    node: str = ""
    sequence: int = Field(ge=1)
    duration_ms: float | None = Field(default=None, ge=0)
    token_usage: dict[str, int] = Field(default_factory=dict)
    retry_count: int = Field(default=0, ge=0)
    summary: str = Field(min_length=1)
    detail: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list)
    consultation_ids: list[str] = Field(default_factory=list)


class TrajectoryRound(StrictModel):
    index: int = Field(ge=1)
    observation: str | None = None
    entries: list[TrajectoryEntry] = Field(default_factory=list)


class TrajectoryReadModel(StrictModel):
    run_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    rounds: list[TrajectoryRound] = Field(default_factory=list)
    phase_entries: list[TrajectoryEntry] = Field(default_factory=list)
    totals: dict[str, Any] = Field(default_factory=dict)


class ApprovalRequestReadModel(StrictModel):
    run_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    approval_kind: Literal["response"] = "response"
    plan: dict[str, Any] = Field(default_factory=dict)
    requested_at: datetime | None = None
    status: Literal["pending", "decided"] = "pending"


class ApprovalDecision(StrictModel):
    """Agent-Inbox four-state semantics: accept / edit / respond / ignore."""

    decision: ApprovalDecisionKind
    decided_by: str = Field(min_length=1)
    comment: str | None = None
    edited_plan: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _check_state_dependencies(self) -> "ApprovalDecision":
        if self.decision == "edit" and not self.edited_plan:
            raise ValueError("edit decision requires edited_plan")
        if self.decision == "respond" and not (self.comment or "").strip():
            raise ValueError("respond decision requires a comment")
        return self


class CheckpointRef(StrictModel):
    checkpoint_id: str = Field(min_length=1)
    parent_checkpoint_id: str | None = None
    step: int = Field(ge=-1)  # langgraph's pre-start checkpoint carries step -1
    node: str | None = None
    created_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class DebugStateSummary(StrictModel):
    checkpoint: CheckpointRef
    node_summaries: dict[str, Any] = Field(default_factory=dict)
