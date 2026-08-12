from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import Field

from ..shared import StrictModel
from .common import ContractModel
from .evidence import Coverage


class VerdictLevel(str, Enum):
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    LIKELY_MALICIOUS = "likely_malicious"
    SUSPICIOUS = "suspicious"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    LIKELY_BENIGN = "likely_benign"
    BENIGN = "benign"


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


class CandidateVerdict(StrictModel):
    level: VerdictLevel
    threat_type: Literal["backdoor_c2", "data_exfiltration", "ransomware", "other", "unknown"]
    summary: str
    supporting_refs: list[str] = Field(default_factory=list)
    contradicting_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class JudgmentResult(ContractModel):
    verdict: CandidateVerdict
    facts: list[Fact] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    coverage: dict[str, Coverage] = Field(default_factory=dict)
    active_scenarios: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
