from __future__ import annotations

from typing import Any

from pydantic import Field

from .common import ContractModel
from .investigation import JudgmentResult
from .response import ResponsePlan


class CaseReadModel(ContractModel):
    lifecycle_status: str
    judgment: JudgmentResult | None = None
    response_plan: ResponsePlan | None = None
    entities: list[dict[str, Any]] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)
    analysis_notes: list[str] = Field(default_factory=list)
    investigation_timeline: list[dict[str, Any]] = Field(default_factory=list)
    approval_status: str | None = None
    limitations: list[str] = Field(default_factory=list)
