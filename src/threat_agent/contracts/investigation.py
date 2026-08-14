from __future__ import annotations

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


class CandidateVerdict(StrictModel):
    level: VerdictLevel
    threat_type: Literal["backdoor_c2", "data_exfiltration", "ransomware", "other", "unknown"]
    summary: str
    supporting_refs: list[str] = Field(default_factory=list)
    contradicting_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class JudgmentResult(ContractModel):
    verdict: CandidateVerdict
    evidence_refs: list[str] = Field(default_factory=list)
    asserted_host_refs: list[str] = Field(default_factory=list)
    coverage: dict[str, Coverage] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
