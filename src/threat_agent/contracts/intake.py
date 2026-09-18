"""Intake contracts (Feature 17): real alert ingestion as a first-class case
source. Reference datasets remain an alternative source for controlled runs."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from ..shared import StrictModel


class AlertIntakeRequest(StrictModel):
    tenant_id: str = Field(min_length=1)
    source: Literal["alert_json", "reference_dataset"] = "alert_json"
    # Required for alert_json; meaningless for reference_dataset sources.
    alert_id: str | None = None
    host_ref: str | None = None
    file_path: str | None = None
    file_sha256: str | None = None
    detected_at: datetime | None = None
    summary: str | None = None
    # Original alert payload, persisted verbatim into the run ledger.
    raw: dict[str, Any] = Field(default_factory=dict)
    # Alternative source: versioned reference dataset preset.
    reference_dataset_id: str | None = None
    profile_id: str | None = None

    @model_validator(mode="after")
    def _check_source_dependencies(self) -> "AlertIntakeRequest":
        if self.source == "alert_json":
            missing = [
                name
                for name in ("alert_id", "host_ref", "file_sha256", "file_path")
                if not getattr(self, name)
            ]
            if missing:
                raise ValueError(f"alert_json intake requires: {', '.join(missing)}")
        if self.source == "reference_dataset" and not (
            self.reference_dataset_id and self.profile_id
        ):
            raise ValueError(
                "reference_dataset intake requires reference_dataset_id and profile_id"
            )
        return self
