from __future__ import annotations

from typing import Annotated, Any, Literal, TypeAlias

from pydantic import Field

from ...contracts.evidence import Entity, Scope
from ...contracts import InvestigationReport, InvestigationToolLedger
from ...contracts.investigation import CandidateVerdict
from ...shared import StrictModel


class Claim(StrictModel):
    claim_id: str
    claim_type: str
    statement: str
    source_evidence_refs: list[str]
    verification_state: Literal["unverified", "supported", "confirmed", "contradicted"] = "unverified"
    verification_requirements: list[str] = Field(default_factory=list)


class Budget(StrictModel):
    max_iterations: int = 48
    max_tool_calls: int = 60
    iterations_used: int = 0
    tool_calls_used: int = 0
    max_report_rejudgments: int = 2
    report_rejudgments_used: int = 0


class ToolCall(StrictModel):
    call_id: str
    tool_name: str
    action_type: str
    status: Literal["success", "empty", "partial", "unavailable", "denied", "error"]
    objective: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class FinishRequest(StrictModel):
    action_type: Literal["finish_request"] = "finish_request"
    objective: str = Field(min_length=10)


class DataToolRequest(StrictModel):
    action_type: Literal["data_tool_request"] = "data_tool_request"
    tool_name: Literal[
        "query_process_activities", "query_network_activities", "query_socket_activities",
        "query_file_activities", "query_service_activities", "query_package_activities",
        "query_asset_activities", "explore_entity", "get_raw_records", "calculate_activity_metrics",
    ]
    objective: str = Field(min_length=10)
    arguments: dict[str, Any] = Field(default_factory=dict)
    tool_call_id: str | None = None
    model_message: dict[str, Any] = Field(default_factory=dict)


InvestigationAction: TypeAlias = Annotated[
    DataToolRequest | FinishRequest,
    Field(discriminator="action_type"),
]


class InvestigationState(StrictModel):
    case_id: str
    raw_input: dict[str, Any]
    entities: list[Entity]
    claims: list[Claim] = Field(default_factory=list)
    scope: Scope
    budget: Budget = Field(default_factory=Budget)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    verdict: CandidateVerdict | None = None
    tool_ledger: InvestigationToolLedger = Field(default_factory=InvestigationToolLedger)
    investigation_report: InvestigationReport | None = None
    report_validation_errors: list[str] = Field(default_factory=list)
    finished: bool = False
