from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import Field

from ..shared import StrictModel


SCHEMA_VERSION = "1.0"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ContractModel(StrictModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    tenant_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=utc_now)
    source_identity: str = Field(default="system", min_length=1)
