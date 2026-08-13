from __future__ import annotations

from typing import Any, Protocol

from ...contracts import DatasetManifest, IngestionReport, NormalizedActivity, RawRecordEnvelope


class SourceParser(Protocol):
    name: str
    version: str

    def parse(
        self, record: RawRecordEnvelope, payload: dict[str, Any]
    ) -> list[NormalizedActivity]: ...


class ActivityIngestionStore(Protocol):
    def begin_batch(self, manifest: DatasetManifest) -> None: ...

    def raw_record_exists(self, tenant_id: str, source_system: str, source_record_id: str) -> bool: ...

    def raw_record_digest(
        self, tenant_id: str, source_system: str, source_record_id: str
    ) -> str | None: ...

    def put_record_with_activities(
        self,
        manifest: DatasetManifest,
        record: RawRecordEnvelope,
        payload: dict[str, Any],
        activities: list[NormalizedActivity],
    ) -> None: ...

    def quarantine_record(
        self,
        manifest: DatasetManifest,
        source_record_id: str,
        payload: dict[str, Any],
        error_type: str,
        message: str,
    ) -> None: ...

    def finalize_batch(self, manifest: DatasetManifest, report: IngestionReport) -> None: ...
