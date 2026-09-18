from __future__ import annotations

from typing import Literal

from pydantic import Field

from ..shared import StrictModel
from .common import ContractModel


class ResponseAction(StrictModel):
    action_id: str
    action_type: str
    target_refs: list[str] = Field(default_factory=list)
    rationale: str
    judgment_refs: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    expected_impact: str
    approval_class: Literal["none", "operator", "security_lead", "business_owner"]
    rollback_steps: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    # 知识引用：knowledge_id@version#chunk_id，凭此事后追溯（设计 §5）
    knowledge_refs: list[str] = Field(default_factory=list)


class ResponsePlan(ContractModel):
    judgment_schema_version: str
    status: Literal["recommended", "approval_required", "insufficient_context", "rejected"]
    actions: list[ResponseAction] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)
    residual_risk: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
