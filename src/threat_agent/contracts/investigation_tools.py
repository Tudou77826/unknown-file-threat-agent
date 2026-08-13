from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from ..shared import StrictModel
from .activity import EntityIdentity, NormalizedActivity, ObservedRelation
from .data_boundary import ActivityQueryResult
from .evidence import Scope


ActivityType = Literal["process", "network", "socket", "file", "service", "package", "asset", "extension"]


class ToolRuntimeContext(StrictModel):
    tenant_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    scope: Scope


class QueryActivitiesInput(StrictModel):
    activity_type: ActivityType
    host_refs: list[str] = Field(default_factory=list)
    entity_refs: list[str] = Field(default_factory=list)
    start_time: datetime | None = None
    end_time: datetime | None = None
    filters: dict[str, Any] = Field(default_factory=dict)
    cursor: str | None = None
    limit: int = Field(default=200, ge=1, le=1000)

    @model_validator(mode="after")
    def validate_time_range(self) -> "QueryActivitiesInput":
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValueError("start_time cannot be after end_time")
        return self


class ExploreEntityInput(StrictModel):
    entity_ref: str = Field(min_length=1)
    include: list[Literal["identity", "relations", "timeline"]] = Field(
        default_factory=lambda: ["identity", "relations", "timeline"]
    )
    relation_direction: Literal["inbound", "outbound", "both"] = "both"
    start_time: datetime | None = None
    end_time: datetime | None = None
    cursor: str | None = None
    limit: int = Field(default=200, ge=1, le=1000)


class EntityExplorationResult(StrictModel):
    identity: EntityIdentity | None = None
    resolved_relations: list[ObservedRelation] = Field(default_factory=list)
    candidate_relations: list[ObservedRelation] = Field(default_factory=list)
    timeline: list[NormalizedActivity] = Field(default_factory=list)
    returned_count: int = Field(ge=0)
    next_cursor: str | None = None


class GetRawRecordsInput(StrictModel):
    activity_refs: list[str] = Field(min_length=1, max_length=10)
    field_paths: list[str] = Field(default_factory=list, max_length=20)
    max_records: int = Field(default=10, ge=1, le=10)


class RawRecordView(StrictModel):
    activity_ref: str
    raw_record_ref: str
    source_system: str
    source_record_id: str
    observed_at: datetime
    payload: dict[str, Any]


class RawRecordResult(StrictModel):
    records: list[RawRecordView] = Field(default_factory=list)
    truncated: bool = False


class CalculateActivityMetricsInput(StrictModel):
    operation: Literal[
        "process_tree", "connection_pattern", "transfer_summary", "file_change_summary"
    ]
    activity_refs: list[str] = Field(min_length=1, max_length=1000)
    parameters: dict[str, Any] = Field(default_factory=dict)


class ActivityMetricResult(StrictModel):
    operation: str
    activity_refs: list[str]
    metrics: dict[str, Any]
    limitations: list[str] = Field(default_factory=list)


class InvestigationToolTrace(StrictModel):
    sequence: int = Field(ge=1)
    tool_name: Literal[
        "query_activities", "explore_entity", "get_raw_records", "calculate_activity_metrics"
    ]
    arguments: dict[str, Any]
    result_type: str
    result: dict[str, Any]
    tool_call_id: str | None = None
    model_message: dict[str, Any] = Field(default_factory=dict)


class InvestigationToolLedger(StrictModel):
    query_results: list[ActivityQueryResult] = Field(default_factory=list)
    entity_results: list[EntityExplorationResult] = Field(default_factory=list)
    raw_record_results: list[RawRecordResult] = Field(default_factory=list)
    metric_results: list[ActivityMetricResult] = Field(default_factory=list)
    traces: list[InvestigationToolTrace] = Field(default_factory=list)
    authorized_activity_refs: list[str] = Field(default_factory=list)
