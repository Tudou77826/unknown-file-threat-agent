"""Internal candidate report model (Feature 14).

A ``ReportDraft`` is a mutable candidate: it flows through grounding
validation, constrained rejudgment and the evidence gate, and is never
persisted or exposed as an investigation result. Only ``ReportPublisher``
turns a draft into a formal ``InvestigationReport``.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

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
    asserted_start: Any | None = None
    asserted_end: Any | None = None
    confirmed_relation_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
