from datetime import datetime, timezone

import pytest
from pydantic import TypeAdapter, ValidationError

from threat_agent.contracts import (
    ActivityQueryResult,
    Evidence,
    EvidenceReference,
    EvidenceStatus,
    ExtensionActivity,
    InvestigationReport,
    InvestigationRun,
    NormalizedActivity,
    OperationalEvent,
    ObservedRelation,
    ProcessActivity,
    QueryExecutionBoundary,
    QueryFieldDefinition,
    QueryInterfaceDefinition,
    QueryScopeSnapshot,
    RawRecordEnvelope,
)
from threat_agent.contracts.investigation import CandidateVerdict, VerdictLevel


NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)


def tenant_fields() -> dict:
    return {
        "tenant_id": "tenant-a",
        "created_at": NOW,
        "source_identity": "test-suite",
    }


def process_activity() -> ProcessActivity:
    return ProcessActivity(
        **tenant_fields(),
        activity_id="activity-process-1",
        observed_at=NOW,
        ingested_at=NOW,
        source_system="edr-a",
        source_record_id="source-1",
        subject_refs=["process-1"],
        actor_refs=["user-root"],
        target_refs=["file-1"],
        raw_record_ref="raw-record-1",
        normalizer_version="edr-a/1.0",
        host_ref="host-1",
        process_ref="process-1",
        pid=123,
        process_started_at=NOW,
        executable="/tmp/sysupd",
        operation="execute",
    )


def test_raw_record_and_activity_are_tenant_scoped_not_case_owned():
    raw = RawRecordEnvelope(
        **tenant_fields(),
        raw_record_id="raw-record-1",
        source_system="edr-a",
        source_record_id="source-1",
        observed_at=NOW,
        ingested_at=NOW,
        connector_version="connector/1.0",
        parser_version="parser/1.0",
        payload_ref="object://raw-record-1",
        payload_digest="sha256:abc",
    )
    activity = process_activity()
    assert "case_id" not in raw.model_dump()
    assert "case_id" not in activity.model_dump()
    assert TypeAdapter(NormalizedActivity).validate_json(activity.model_dump_json()) == activity


def test_same_activity_can_be_referenced_by_two_cases_without_copying_it():
    activity = process_activity()
    references = [
        EvidenceReference(
            **tenant_fields(),
            case_id=case_id,
            run_id=f"run-{case_id}",
            evidence_id=f"evidence-{case_id}",
            query_id=f"query-{case_id}",
            activity_ref=activity.activity_id,
            observed_at=NOW,
        )
        for case_id in ("case-a", "case-b")
    ]
    assert references[0].activity_ref == references[1].activity_ref
    assert references[0].case_id != references[1].case_id


def test_extension_activity_requires_standard_envelope_and_payload():
    payload = {
        **tenant_fields(),
        "activity_id": "activity-extension-1",
        "observed_at": NOW,
        "ingested_at": NOW,
        "source_system": "special-sensor",
        "source_record_id": "special-1",
        "subject_refs": ["host-1"],
        "raw_record_ref": "raw-special-1",
        "normalizer_version": "special/1.0",
        "extension_schema": "vendor/product/event/1.0",
        "extension": {},
    }
    with pytest.raises(ValidationError, match="non-empty extension"):
        ExtensionActivity(**payload)
    payload.pop("raw_record_ref")
    payload["extension"] = {"vendor_field": "value"}
    with pytest.raises(ValidationError, match="raw_record_ref"):
        ExtensionActivity(**payload)


def query_interface() -> QueryInterfaceDefinition:
    return QueryInterfaceDefinition(
        **tenant_fields(),
        interface_id="process-activity-query",
        interface_version="1.0",
        activity_types=["process"],
        fields=[
            QueryFieldDefinition(
                name="process_ref", value_type="string", semantic="平台进程实体引用", nullable=False
            )
        ],
        supported_filters=["host_ref", "process_ref", "observed_at"],
        correlation_keys=["host_ref", "process_ref", "process_started_at"],
        max_page_size=1000,
        max_time_range_seconds=86400,
    )


def test_activity_query_result_keeps_activity_and_evidence_reference_consistent():
    activity = process_activity()
    reference = EvidenceReference(
        **tenant_fields(),
        case_id="case-a",
        run_id="run-a",
        evidence_id="evidence-a",
        query_id="query-a",
        activity_ref=activity.activity_id,
        observed_at=NOW,
    )
    result = ActivityQueryResult(
        **tenant_fields(),
        case_id="case-a",
        run_id="run-a",
        query_id="query-a",
        activities=[activity],
        evidence_references=[reference],
        interface_definition=query_interface(),
        execution_boundary=QueryExecutionBoundary(
            interface_id="process-activity-query",
            interface_version="1.0",
            requested_scope=QueryScopeSnapshot(host_refs=["host-1"]),
            applied_scope=QueryScopeSnapshot(host_refs=["host-1"]),
            returned_count=1,
            page_limit=100,
            source_systems=["edr-a"],
            executed_at=NOW,
        ),
    )
    assert ActivityQueryResult.model_validate_json(result.model_dump_json()) == result


def test_relation_resolution_does_not_silently_upgrade_candidates():
    with pytest.raises(ValidationError, match="candidate relation requires ambiguity_reason"):
        ObservedRelation(
            **tenant_fields(),
            relation_id="relation-1",
            relation_type="possibly_same_process",
            source_entity_ref="process-a",
            target_entity_ref="process-b",
            resolution_status="candidate",
            confidence=0.62,
            resolver_version="resolver/1.0",
        )
    with pytest.raises(ValidationError, match="resolved relation requires"):
        ObservedRelation(
            **tenant_fields(),
            relation_id="relation-2",
            relation_type="spawned",
            source_entity_ref="process-a",
            target_entity_ref="process-b",
            resolution_status="resolved",
            confidence=1,
            resolver_version="resolver/1.0",
        )


def test_report_and_run_contracts_round_trip():
    report = InvestigationReport(
        **tenant_fields(),
        case_id="case-a",
        report_id="report-a",
        report_version=1,
        run_id="run-a",
        verdict=CandidateVerdict(
            level=VerdictLevel.INSUFFICIENT_EVIDENCE,
            threat_type="unknown",
            summary="当前数据不足以完成定性。",
        ),
        executive_summary="当前仅能确认文件告警，缺少进程网络数据。",
        unresolved_questions=["未知文件是否建立外部连接？"],
        query_boundary_refs=["query-network-1"],
        producer="judgment-report-graph",
        model_version="model-test",
        prompt_version="report/1.0",
    )
    run = InvestigationRun(
        **tenant_fields(),
        case_id="case-a",
        run_id="run-a",
        status="completed",
        stage="published",
        started_at=NOW,
        completed_at=NOW,
        report_id=report.report_id,
    )
    event = OperationalEvent(
        **tenant_fields(),
        case_id="case-a",
        run_id="run-a",
        event_id="event-a",
        sequence=1,
        event_type="model",
        stage="report",
        duration_ms=12.5,
        token_usage={"input": 10, "output": 20},
        correlation_id="correlation-a",
    )
    assert InvestigationReport.model_validate_json(report.model_dump_json()) == report
    assert InvestigationRun.model_validate_json(run.model_dump_json()) == run
    assert OperationalEvent.model_validate_json(event.model_dump_json()) == event
