from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from threat_agent.contracts import DatasetManifest
from threat_agent.data_foundation import (
    BatchIngestionService,
    ReferenceEventParser,
    SQLiteActivityStore,
    VendorEnvelopeParser,
)


NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)


def manifest(parser, *, batch_id: str = "batch-1", expected: int | None = None):
    return DatasetManifest(
        tenant_id="tenant-a",
        source_identity="test-suite",
        dataset_id="dataset-a",
        dataset_version="1.0",
        batch_id=batch_id,
        source_system="batch-connector",
        connector_version="connector/1.0",
        parser_name=parser.name,
        parser_version=parser.version,
        expected_activity_domains=["process", "network", "file"],
        expected_record_count=expected,
    )


def reference_process() -> dict:
    return {
        "event_id": "event-process-1",
        "event_type": "process_exec",
        "domain": "process",
        "source_system": "edr-process",
        "observed_at": "2026-04-23T03:20:44.221Z",
        "host_id": "host-1",
        "subject_refs": ["file:host-1:abc", "process:host-1:123:1776914444221"],
        "data": {
            "file_ref": "file:host-1:abc",
            "process_ref": "process:host-1:123:1776914444221",
            "executable": "/tmp/sysupd",
            "cmdline": "/tmp/sysupd",
        },
    }


def vendor_process() -> dict:
    return {
        "id": "vendor-process-1",
        "category": "process",
        "device": {"id": "host-1"},
        "entity": {"id": "process:host-1:123:1776914444221"},
        "event": {
            "time": "2026-04-23T03:20:44.221Z",
            "pid": 123,
            "started_at": "2026-04-23T03:20:44.221Z",
            "image": "/tmp/sysupd",
            "command_line": "/tmp/sysupd",
            "operation": "execute",
        },
    }


def test_two_source_parsers_produce_equivalent_process_semantics(tmp_path: Path):
    reference_store = SQLiteActivityStore(tmp_path / "reference.sqlite")
    vendor_store = SQLiteActivityStore(tmp_path / "vendor.sqlite")
    try:
        ref_parser = ReferenceEventParser()
        vendor_parser = VendorEnvelopeParser()
        BatchIngestionService(reference_store, ref_parser).ingest_payloads(
            manifest(ref_parser), [reference_process()], ingested_at=NOW
        )
        BatchIngestionService(vendor_store, vendor_parser).ingest_payloads(
            manifest(vendor_parser), [vendor_process()], ingested_at=NOW
        )
        ref = next(item for item in reference_store.list_activities("tenant-a") if item.activity_type == "process")
        vendor = vendor_store.list_activities("tenant-a")[0]
        assert (ref.host_ref, ref.pid, ref.executable, ref.operation) == (
            vendor.host_ref, vendor.pid, vendor.executable, vendor.operation
        )
        assert ref.source_system == "edr-process"
        assert vendor.source_system == "batch-connector"
    finally:
        reference_store.close()
        vendor_store.close()


def test_import_is_idempotent_and_conflicting_record_is_quarantined(tmp_path: Path):
    store = SQLiteActivityStore(tmp_path / "activity.sqlite")
    parser = ReferenceEventParser()
    service = BatchIngestionService(store, parser)
    try:
        first = service.ingest_payloads(manifest(parser), [reference_process()], ingested_at=NOW)
        duplicate = service.ingest_payloads(manifest(parser), [reference_process()], ingested_at=NOW)
        changed = reference_process()
        changed["data"] = {**changed["data"], "cmdline": "/tmp/sysupd --changed"}
        conflict = service.ingest_payloads(manifest(parser), [changed], ingested_at=NOW)
        assert (first.imported_records, first.produced_activities) == (1, 2)
        assert duplicate.duplicate_records == 1
        assert conflict.failed_records == 1
        assert store.count_raw_records("tenant-a") == 1
        assert store.count_activities("tenant-a") == 2
        assert store.count_quarantined("tenant-a", "batch-1") == 1
    finally:
        store.close()


def test_partial_import_reports_observed_failures_without_quality_grading(tmp_path: Path):
    store = SQLiteActivityStore(tmp_path / "partial.sqlite")
    parser = ReferenceEventParser()
    try:
        report = BatchIngestionService(store, parser).ingest_payloads(
            manifest(parser, batch_id="partial", expected=2),
            [reference_process(), {"event_id": "broken"}],
            ingested_at=NOW,
        )
        assert report.status == "partial"
        assert report.failed_records == 1
        assert report.limitations == []
        assert store.count_quarantined("tenant-a", "partial") == 1
    finally:
        store.close()


def test_reference_c2_records_cover_all_seven_initial_activity_domains(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    payloads = []
    for path in sorted((root / "cases" / "c2_malicious" / "events").glob("*.jsonl")):
        payloads.extend(
            json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
        )
    store = SQLiteActivityStore(tmp_path / "c2.sqlite")
    parser = ReferenceEventParser()
    try:
        report = BatchIngestionService(store, parser).ingest_payloads(
            manifest(parser, batch_id="c2", expected=len(payloads)), payloads, ingested_at=NOW
        )
        assert report.status == "completed"
        assert set(report.activity_domains) == {
            "asset", "file", "network", "package", "process", "service", "socket"
        }
        assert store.count_raw_records("tenant-a") == len(payloads)
        assert store.count_activities("tenant-a") > len(payloads)
    finally:
        store.close()


def test_jsonl_entrypoint_persists_payload_and_report(tmp_path: Path):
    source = tmp_path / "events.jsonl"
    source.write_text(json.dumps(reference_process()) + "\n", encoding="utf-8")
    store = SQLiteActivityStore(tmp_path / "jsonl.sqlite")
    parser = ReferenceEventParser()
    try:
        report = BatchIngestionService(store, parser).ingest_jsonl(
            manifest(parser), source, ingested_at=NOW
        )
        assert report.received_records == 1
        assert report.imported_records == 1
    finally:
        store.close()
