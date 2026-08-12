from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from ..shared import StrictModel
from .common import ContractModel, SCHEMA_VERSION
from .evidence import Coverage, EvidenceStatus
from .presentation import CaseReadModel


class DemoSchemaModel(StrictModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION


class SourceCoverageRule(StrictModel):
    source_id: str = Field(min_length=1)
    domains: list[str] = Field(min_length=1)
    status: EvidenceStatus
    completeness: Literal["complete", "partial", "unknown", "unavailable"]
    limitations: list[str] = Field(default_factory=list)


class DataProfile(DemoSchemaModel):
    profile_id: str = Field(min_length=1)
    dataset_version: str = Field(min_length=1)
    level: Literal["l0", "l1", "l2", "l3"]
    visible_sources: list[str] = Field(default_factory=list)
    coverage_rules: list[SourceCoverageRule] = Field(default_factory=list)
    asset_context_visible: bool = False
    description: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_sources(self) -> "DataProfile":
        if len(self.visible_sources) != len(set(self.visible_sources)):
            raise ValueError("visible_sources must be unique")
        rule_sources = [rule.source_id for rule in self.coverage_rules]
        if len(rule_sources) != len(set(rule_sources)):
            raise ValueError("coverage_rules must contain unique source_id values")
        return self


class ReferenceDatasetMetadata(DemoSchemaModel):
    dataset_id: str
    dataset_version: str
    scenario: str
    label: Literal["malicious_reference", "benign_reference"]
    random_seed: int
    content_digest: str


class ReferenceAsset(StrictModel):
    host_id: str
    asset_name: str
    environment: Literal["production", "staging", "test", "development"]
    business_system: str
    criticality: Literal["low", "medium", "high", "critical"]
    business_owner: str
    security_owner: str
    maintenance_window: str
    isolation_policy: Literal["allowed", "security_approval", "dual_approval", "prohibited"]
    isolation_impact: str


class ReadinessQuestion(StrictModel):
    question_id: str
    question: str
    evidence_role_ids: list[str] = Field(default_factory=list)
    required_domains: list[str] = Field(default_factory=list)
    required_sources: list[str] = Field(default_factory=list)
    status: Literal["answerable", "partially_answerable", "blocked"]
    limitations: list[str] = Field(default_factory=list)


class DataReadinessReport(ContractModel):
    run_id: str
    profile_id: str
    dataset_version: str
    available_sources: list[str] = Field(default_factory=list)
    missing_sources: list[str] = Field(default_factory=list)
    answerable_questions: list[ReadinessQuestion] = Field(default_factory=list)
    blocked_questions: list[ReadinessQuestion] = Field(default_factory=list)
    coverage_summary: dict[str, Coverage] = Field(default_factory=dict)
    recommended_capabilities: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ProfileComparisonItem(StrictModel):
    profile_id: str
    level: Literal["l0", "l1", "l2", "l3"]
    readiness: DataReadinessReport
    case: CaseReadModel
    new_fact_ids: list[str] = Field(default_factory=list)
    new_finding_ids: list[str] = Field(default_factory=list)


class DemoComparisonReadModel(DemoSchemaModel):
    dataset_id: str
    dataset_version: str
    reference_data_notice: str
    fixed_conditions: dict[str, Any] = Field(default_factory=dict)
    profiles: list[ProfileComparisonItem] = Field(min_length=1)
