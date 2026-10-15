"""Additional read capabilities of an existing situational-awareness system."""

from __future__ import annotations

from typing import Protocol

from ...contracts.situational_awareness import (
    AlertQuery, AssessmentQuery, AssetInfo, DataQueryContext, FileHash,
    FileReputation, QueryPage, SourceAssessment, UnknownFileAlert,
)
from .investigation_data import InvestigationDataPort


class SituationalAwarenessDataPort(InvestigationDataPort, Protocol):
    def query_alerts(self, query: AlertQuery) -> QueryPage[UnknownFileAlert]: ...

    def query_file_reputation(
        self, context: DataQueryContext, file_hash: FileHash
    ) -> FileReputation: ...

    def get_asset_info(
        self, context: DataQueryContext, host_ref: str
    ) -> AssetInfo | None: ...

    def query_source_assessments(
        self, query: AssessmentQuery
    ) -> QueryPage[SourceAssessment]: ...
