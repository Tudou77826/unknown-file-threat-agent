from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ...contracts import DatasetManifest, IngestionFailure, IngestionReport, RawRecordEnvelope
from ..ports import ActivityIngestionStore, SourceParser


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _source_record_id(payload: dict[str, Any]) -> str:
    value = payload.get("event_id") or payload.get("id") or payload.get("record_id")
    if not value:
        raise ValueError("source record requires event_id, id, or record_id")
    return str(value)


def _observed_at(payload: dict[str, Any]) -> datetime:
    value = payload.get("observed_at")
    if value is None and isinstance(payload.get("event"), dict):
        value = payload["event"].get("observed_at") or payload["event"].get("time")
    if value is None:
        raise ValueError("source record requires observed_at or event.time")
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("source record time must include a timezone")
    return parsed


class BatchIngestionService:
    def __init__(self, store: ActivityIngestionStore, parser: SourceParser):
        self.store = store
        self.parser = parser

    def ingest_payloads(
        self,
        manifest: DatasetManifest,
        payloads: Iterable[dict[str, Any]],
        *,
        ingested_at: datetime | None = None,
    ) -> IngestionReport:
        if manifest.parser_name != self.parser.name or manifest.parser_version != self.parser.version:
            raise ValueError("manifest parser identity does not match selected parser")
        now = ingested_at or datetime.now(timezone.utc)
        self.store.begin_batch(manifest)
        received = imported = duplicates = produced = 0
        failures: list[IngestionFailure] = []
        times: list[datetime] = []
        domains: set[str] = set()

        for position, payload in enumerate(payloads, start=1):
            received += 1
            source_id = str(payload.get("event_id") or payload.get("id") or payload.get("record_id") or f"line-{position}")
            try:
                source_id = _source_record_id(payload)
                observed = _observed_at(payload)
                record_source = str(payload.get("source_system") or manifest.source_system)
                payload_digest = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
                existing_digest = self.store.raw_record_digest(
                    manifest.tenant_id, record_source, source_id
                )
                if existing_digest is not None:
                    if existing_digest != payload_digest:
                        raise ValueError("source record ID already exists with different content")
                    duplicates += 1
                    continue
                raw_id = "raw-" + hashlib.sha256(
                    f"{manifest.tenant_id}:{record_source}:{source_id}".encode()
                ).hexdigest()[:24]
                record = RawRecordEnvelope(
                    tenant_id=manifest.tenant_id,
                    source_identity="ingestion-service",
                    raw_record_id=raw_id,
                    source_system=record_source,
                    source_record_id=source_id,
                    observed_at=observed,
                    ingested_at=now,
                    connector_version=manifest.connector_version,
                    parser_version=f"{self.parser.name}/{self.parser.version}",
                    payload_ref=f"raw-record://{raw_id}",
                    payload_digest=payload_digest,
                )
                activities = self.parser.parse(record, payload)
                if not activities:
                    raise ValueError("parser produced no normalized activities")
                self.store.put_record_with_activities(manifest, record, payload, activities)
                imported += 1
                produced += len(activities)
                times.append(observed)
                domains.update(item.activity_type for item in activities)
            except Exception as error:
                failure = IngestionFailure(
                    source_record_id=source_id,
                    error_type=type(error).__name__,
                    message=str(error)[:1000],
                )
                failures.append(failure)
                self.store.quarantine_record(
                    manifest, source_id, payload, failure.error_type, failure.message
                )

        failed = len(failures)
        status = "failed" if failed == received and received else "partial" if failed else "completed"
        limitations = []
        if manifest.expected_record_count is not None and received != manifest.expected_record_count:
            limitations.append(
                f"Manifest expected {manifest.expected_record_count} records but received {received}"
            )
        report = IngestionReport(
            tenant_id=manifest.tenant_id,
            source_identity="ingestion-service",
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            batch_id=manifest.batch_id,
            status=status,
            received_records=received,
            imported_records=imported,
            duplicate_records=duplicates,
            failed_records=failed,
            produced_activities=produced,
            actual_start=min(times) if times else None,
            actual_end=max(times) if times else None,
            activity_domains=sorted(domains),
            failures=failures,
            limitations=limitations,
        )
        self.store.finalize_batch(manifest, report)
        return report

    def ingest_jsonl(
        self,
        manifest: DatasetManifest,
        path: Path,
        *,
        ingested_at: datetime | None = None,
    ) -> IngestionReport:
        payloads = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        return self.ingest_payloads(manifest, payloads, ingested_at=ingested_at)
