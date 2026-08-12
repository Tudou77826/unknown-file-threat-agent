from __future__ import annotations

from pydantic import Field

from ...contracts import ResponseAction
from ...shared import StrictModel


class ResponseProposal(StrictModel):
    actions: list[ResponseAction] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)
    residual_risk: list[str] = Field(default_factory=list)
