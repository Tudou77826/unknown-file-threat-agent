from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from threat_agent.contracts import DatasetManifest, EvidenceQuery, ProcessActivityQuery, Scope
from threat_agent.data_foundation import (
    ActivityEvidenceQueryAdapter,
    BatchIngestionService,
    DataAccessError,
    ReferenceEventParser,
    SQLiteActivityQueryAdapter,
    SQLiteActivityStore,
)


NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)


def _manifest() -> DatasetManifest:
    return DatasetManifest(
        tenant_id="tenant-a", dataset_id="dataset", dataset_version="1",
        batch_id="batch", source_system="reference", connector_version="1",
        parser_name="reference-event", parser_version="1.0",
    )


def _event(event_id: str, timestamp: str, process_ref: str) -> dict:
    return {
        "event_id": event_id, "event_type": "process_exec", "domain": "process",
        "source_system": "edr-process", "observed_at": timestamp, "host_id": "host-1",
        "subject_refs": [process_ref, "file:host-1:sha256"],
        "data": {"process_ref": process_ref, "file_ref": "file:host-1:sha256", "executable": "/tmp/a"},
    }


def _scope() -> Scope:
    return Scope(host_ids=["host-1"], start_time=datetime(2026, 4, 23, tzinfo=timezone.utc),
                 end_time=datetime(2026, 4, 24, tzinfo=timezone.utc))


def _seed(store: SQLiteActivityStore) -> None:
    BatchIngestionService(store, ReferenceEventParser()).ingest_payloads(
        _manifest(),
        [
            _event("one", "2026-04-23T03:20:44Z", "process:host-1:123:1776914444000"),
            _event("two", "2026-04-23T04:20:44Z", "process:host-1:123:1776918044000"),
        ],
        ingested_at=NOW,
    )


def _query(**overrides) -> ProcessActivityQuery:
    values = dict(
        tenant_id="tenant-a", case_id="case-a", run_id="run-a", query_id="query-a",
        scope=_scope(), host_refs=["host-1"], source_event_types=["process_exec"], limit=1,
    )
    values.update(overrides)
    return ProcessActivityQuery(**values)


def test_entity_projection_separates_same_pid_with_different_lifecycles(tmp_path: Path):
    store = SQLiteActivityStore(tmp_path / "activities.sqlite")
    try:
        _seed(store)
        processes = [item for item in store.list_entities("tenant-a") if item.entity_type == "process"]
        assert len(processes) == 2
        assert len({item.entity_id for item in processes}) == 2
        assert {item.attributes["pid"] for item in processes} == {123}
    finally:
        store.close()


def test_typed_query_returns_interface_execution_facts_and_stable_pagination(tmp_path: Path):
    store = SQLiteActivityStore(tmp_path / "activities.sqlite")
    try:
        _seed(store)
        adapter = SQLiteActivityQueryAdapter(store)
        first = adapter.query_process(_query())
        assert first.execution_boundary.returned_count == 1
        assert first.execution_boundary.next_cursor
        assert first.execution_boundary.source_systems == ["edr-process"]
        assert "process_refs" in first.interface_definition.supported_filters
        assert first.evidence_references[0].activity_ref == first.activities[0].activity_id
        second = adapter.query_process(_query(query_id="query-b", cursor=first.execution_boundary.next_cursor))
        assert len(second.activities) == 1
        assert second.activities[0].activity_id != first.activities[0].activity_id
        assert second.execution_boundary.next_cursor is None
        entity_id = next(
            item.entity_id for item in store.list_entities("tenant-a")
            if item.entity_type == "process" and item.attributes.get("started_at") == "2026-04-23T03:20:44+00:00"
        )
        by_entity = adapter.query_process(_query(query_id="query-entity", entity_refs=[entity_id], limit=10))
        assert len(by_entity.activities) == 1
    finally:
        store.close()


def test_empty_query_is_only_an_observed_zero_result(tmp_path: Path):
    store = SQLiteActivityStore(tmp_path / "activities.sqlite")
    try:
        _seed(store)
        result = SQLiteActivityQueryAdapter(store).query_process(
            _query(executable="/does/not/exist")
        )
        assert result.activities == []
        assert result.execution_boundary.returned_count == 0
        assert result.execution_boundary.source_systems == []
        serialized = result.model_dump_json()
        assert "客户" not in serialized
        assert "unsupported" not in serialized
        assert "partial" not in serialized
        assert "complete" not in serialized
    finally:
        store.close()


def test_scope_expansion_is_rejected_instead_of_silently_applied(tmp_path: Path):
    store = SQLiteActivityStore(tmp_path / "activities.sqlite")
    try:
        with pytest.raises(DataAccessError):
            SQLiteActivityQueryAdapter(store).query_process(_query(host_refs=["host-2"]))
    finally:
        store.close()


def test_offline_test_projection_preserves_analyzer_shape_without_quality_claim(tmp_path: Path):
    store = SQLiteActivityStore(tmp_path / "activities.sqlite")
    try:
        _seed(store)
        adapter = ActivityEvidenceQueryAdapter(SQLiteActivityQueryAdapter(store), run_id="run-a")
        result = adapter.query_evidence(EvidenceQuery(
            tenant_id="tenant-a", case_id="case-a", query_id="test-projection-query",
            domain="process", evidence_types=["process_exec"], scope=_scope(), limit=10,
        ))
        assert len(result.evidence) == 2
        assert {item.evidence_type for item in result.evidence} == {"process_exec"}
        assert result.coverage.completeness == "unknown"
        assert result.coverage.limitations == [
            "Offline deterministic-test projection; no data quality assessment"
        ]
    finally:
        store.close()
