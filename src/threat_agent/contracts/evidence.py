from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import Field

from ..shared import StrictModel
from .common import ContractModel


class EvidenceStatus(str, Enum):
    AVAILABLE = "available"
    EMPTY = "empty"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


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


class Scope(StrictModel):
    host_ids: list[str]
    container_ids: list[str] = Field(default_factory=list)
    entity_ids: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(
        default_factory=lambda: ["process", "file", "network", "persistence", "reputation"]
    )
    start_time: datetime | None = None
    end_time: datetime | None = None
    expansion_policy: Literal["deny", "approval_required", "automatic"] = "approval_required"


class EvidenceBundle(StrictModel):
    status: EvidenceStatus
    evidence: list[Evidence] = Field(default_factory=list)
    coverage: Coverage
    limitations: list[str] = Field(default_factory=list)


class EvidenceQuery(ContractModel):
    query_id: str = Field(min_length=1)
    domain: str = Field(min_length=1)
    evidence_types: list[str] = Field(min_length=1)
    scope: Scope
    parameters: dict[str, Any] = Field(default_factory=dict)
    limit: int = Field(default=1000, ge=1, le=5000)
