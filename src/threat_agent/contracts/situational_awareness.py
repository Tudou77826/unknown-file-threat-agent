"""Source-neutral inputs and results for situational-awareness queries."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import Field, field_validator, model_validator

from ..shared import StrictModel
from .common import TenantContractModel
from .evidence import Scope


T = TypeVar("T")
ReputationList = Literal["baseline", "manual_allowlist", "system_allowlist", "blocklist"]


class DataQueryContext(TenantContractModel):
    scope: Scope

    @model_validator(mode="after")
    def validate_scope(self) -> "DataQueryContext":
        if not self.scope.host_ids:
            raise ValueError("A data query requires an explicit host scope")
        if (self.scope.start_time is not None and self.scope.end_time is not None
                and self.scope.start_time > self.scope.end_time):
            raise ValueError("scope.start_time cannot be after scope.end_time")
        return self


class AlertQuery(DataQueryContext):
    limit: int = Field(default=200, ge=1, le=1000)
    cursor: str | None = None


class AssessmentQuery(AlertQuery):
    entity_refs: list[str] = Field(default_factory=list)


class QueryPage(StrictModel, Generic[T]):
    records: list[T] = Field(default_factory=list)
    next_cursor: str | None = None


class FileHash(StrictModel):
    algorithm: Literal["md5", "sha1", "sha256", "sha512"]
    digest: str = Field(min_length=1)

    @field_validator("algorithm", "digest", mode="before")
    @classmethod
    def normalize_hash(cls, value: Any) -> Any:
        return value.strip().lower() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_digest(self) -> "FileHash":
        lengths = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
        if len(self.digest) != lengths[self.algorithm] or any(
            character not in "0123456789abcdef" for character in self.digest
        ):
            raise ValueError("digest must be hexadecimal and match the hash algorithm")
        return self


class SourceRecord(TenantContractModel):
    source_system: str = Field(min_length=1)
    source_record_id: str | None = None
    raw_reference: str | None = None


class UnknownFileAlert(SourceRecord):
    source_record_id: str = Field(min_length=1)
    host_ref: str = Field(min_length=1)
    detected_at: datetime | None = None
    file_path: str | None = None
    file_hash: FileHash | None = None
    process_ref: str | None = None
    pid: int | None = Field(default=None, ge=0)
    parent_pid: int | None = Field(default=None, ge=0)
    process_name: str | None = None
    container_id: str | None = None


class ReputationMatch(StrictModel):
    list_name: ReputationList
    source_record_id: str | None = None
    scope_description: str | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None


class FileReputation(SourceRecord):
    file_hash: FileHash
    queried_lists: list[ReputationList] = Field(min_length=1)
    matches: list[ReputationMatch] = Field(default_factory=list)
    queried_at: datetime
    notes: str | None = None

    @model_validator(mode="after")
    def validate_matches(self) -> "FileReputation":
        if any(match.list_name not in self.queried_lists for match in self.matches):
            raise ValueError("A reputation match must belong to a queried list")
        return self


class AssetInfo(SourceRecord):
    host_ref: str = Field(min_length=1)
    attributes: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime | None = None


class SourceAssessment(SourceRecord):
    source_record_id: str = Field(min_length=1)
    host_ref: str = Field(min_length=1)
    entity_refs: list[str] = Field(default_factory=list)
    kind: Literal["event", "reputation", "attack_chain"] = "event"
    method: Literal["human", "rule", "model", "unknown"] = "unknown"
    conclusion: str | None = None
    score: float | None = None
    assessed_at: datetime | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
