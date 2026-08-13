from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from ..shared import StrictModel
from .common import TenantContractModel


class DatasetManifest(TenantContractModel):
    dataset_id: str = Field(min_length=1)
    dataset_version: str = Field(min_length=1)
    batch_id: str = Field(min_length=1)
    source_system: str = Field(min_length=1)
    connector_version: str = Field(min_length=1)
    parser_name: str = Field(min_length=1)
    parser_version: str = Field(min_length=1)
    declared_start: datetime | None = None
    declared_end: datetime | None = None
    expected_activity_domains: list[str] = Field(default_factory=list)
    expected_record_count: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_time_range(self) -> "DatasetManifest":
        if self.declared_start and self.declared_end and self.declared_start > self.declared_end:
            raise ValueError("declared_start cannot be after declared_end")
        return self


class IngestionFailure(StrictModel):
    source_record_id: str
    error_type: str
    message: str


class IngestionReport(TenantContractModel):
    dataset_id: str
    dataset_version: str
    batch_id: str
    status: Literal["completed", "partial", "failed"]
    received_records: int = Field(ge=0)
    imported_records: int = Field(ge=0)
    duplicate_records: int = Field(ge=0)
    failed_records: int = Field(ge=0)
    produced_activities: int = Field(ge=0)
    actual_start: datetime | None = None
    actual_end: datetime | None = None
    activity_domains: list[str] = Field(default_factory=list)
    failures: list[IngestionFailure] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_counts(self) -> "IngestionReport":
        if self.imported_records + self.duplicate_records + self.failed_records != self.received_records:
            raise ValueError("ingestion outcome counts must equal received_records")
        if self.failed_records != len(self.failures):
            raise ValueError("failed_records must match failures length")
        if self.status == "completed" and self.failed_records:
            raise ValueError("completed ingestion cannot contain failures")
        return self
