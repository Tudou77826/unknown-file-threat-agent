from __future__ import annotations

from typing import Any

from pydantic import Field

from .common import ContractModel


class ResponseContext(ContractModel):
    """Asset and business context supplied by the data foundation."""

    asset_context: dict[str, Any] = Field(default_factory=dict)
    missing_context: list[str] = Field(default_factory=list)
