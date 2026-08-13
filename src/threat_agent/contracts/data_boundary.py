from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from ..shared import StrictModel
from .activity import NormalizedActivity
from .common import ContractModel, TenantContractModel


class QueryFieldDefinition(StrictModel):
    name: str = Field(min_length=1)
    value_type: Literal["string", "integer", "number", "boolean", "datetime", "object", "array"]
    semantic: str = Field(min_length=1)
    nullable: bool = True


class QueryInterfaceDefinition(TenantContractModel):
    interface_id: str = Field(min_length=1)
    interface_version: str = Field(min_length=1)
    activity_types: list[str] = Field(min_length=1)
    fields: list[QueryFieldDefinition] = Field(min_length=1)
    supported_filters: list[str] = Field(default_factory=list)
    correlation_keys: list[str] = Field(default_factory=list)
    max_page_size: int = Field(ge=1)
    max_time_range_seconds: int | None = Field(default=None, ge=1)
    sort_order: list[str] = Field(default_factory=lambda: ["observed_at", "activity_id"])


class QueryScopeSnapshot(StrictModel):
    host_refs: list[str] = Field(default_factory=list)
    entity_refs: list[str] = Field(default_factory=list)
    start_time: datetime | None = None
    end_time: datetime | None = None
    filters: dict[str, str | int | float | bool | list[str]] = Field(default_factory=dict)


class QueryExecutionBoundary(StrictModel):
    interface_id: str = Field(min_length=1)
    interface_version: str = Field(min_length=1)
    requested_scope: QueryScopeSnapshot
    applied_scope: QueryScopeSnapshot
    returned_count: int = Field(ge=0)
    page_limit: int = Field(ge=1)
    next_cursor: str | None = None
    source_systems: list[str] = Field(default_factory=list)
    executed_at: datetime


class EvidenceReference(ContractModel):
    run_id: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    query_id: str = Field(min_length=1)
    activity_ref: str = Field(min_length=1)
    evidence_role_refs: list[str] = Field(default_factory=list)
    observed_at: datetime | None = None


class ActivityQueryResult(ContractModel):
    run_id: str = Field(min_length=1)
    query_id: str = Field(min_length=1)
    interface_definition: QueryInterfaceDefinition
    execution_boundary: QueryExecutionBoundary
    activities: list[NormalizedActivity] = Field(default_factory=list)
    evidence_references: list[EvidenceReference] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_result(self) -> "ActivityQueryResult":
        activity_ids = {item.activity_id for item in self.activities}
        if any(item.activity_ref not in activity_ids for item in self.evidence_references):
            raise ValueError("evidence reference points to an activity outside this result")
        if self.execution_boundary.returned_count != len(self.activities):
            raise ValueError("returned_count must match activities length")
        if self.interface_definition.interface_id != self.execution_boundary.interface_id:
            raise ValueError("query interface and execution boundary do not match")
        if self.interface_definition.interface_version != self.execution_boundary.interface_version:
            raise ValueError("query interface versions do not match")
        return self
