"""Internal candidate report model (Feature 14).

A ``ReportDraft`` is a mutable candidate: it flows through grounding
validation, constrained rejudgment and the evidence gate, and is never
persisted or exposed as an investigation result. Only ``ReportPublisher``
turns a draft into a formal ``InvestigationReport``.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import Field, model_validator

from ...contracts import ReportStatement
from ...contracts.investigation import CandidateVerdict
from ...shared import StrictModel


class ReportDraft(StrictModel):
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
    # Models emit timestamps as ISO strings, sometimes without a timezone.
    # Coerce at the boundary so downstream comparisons are always aware;
    # malformed values fail validation and take the graded-retry path.
    asserted_start: datetime | None = None
    asserted_end: datetime | None = None
    confirmed_relation_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _normalize_asserted_times(self) -> "ReportDraft":
        if isinstance(self.asserted_start, datetime) and self.asserted_start.tzinfo is None:
            self.asserted_start = self.asserted_start.replace(tzinfo=timezone.utc)
        if isinstance(self.asserted_end, datetime) and self.asserted_end.tzinfo is None:
            self.asserted_end = self.asserted_end.replace(tzinfo=timezone.utc)
        return self
