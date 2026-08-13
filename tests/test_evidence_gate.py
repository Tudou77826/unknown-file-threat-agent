from __future__ import annotations

from datetime import datetime, timezone

from threat_agent.case_management import initialize_state
from threat_agent.contracts import (
    CandidateVerdict,
    InvestigationToolLedger,
    VerdictLevel,
)
from threat_agent.contracts.data_boundary import (
    ActivityQueryResult,
    QueryExecutionBoundary,
    QueryInterfaceDefinition,
    QueryScopeSnapshot,
)
from threat_agent.contracts.activity import (
    FileActivity,
    NetworkActivity,
    ProcessActivity,
)
from threat_agent.judgment.application.evidence_gate import (
    collect_capabilities,
    gate_verdict,
)


NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)


def _state():
    return initialize_state({
        "File_id": "file-a", "File_hash": "a" * 64, "File_path": "/tmp/a",
        "Sub_asset": "host-1", "tenant_id": "tenant-a", "run_id": "run-a",
    })


def _result(activities):
    scope = QueryScopeSnapshot(host_refs=["host-1"])
    boundary = QueryExecutionBoundary(
        interface_id="activity-query/test", interface_version="1",
        requested_scope=scope, applied_scope=scope,
        returned_count=len(activities), page_limit=200, executed_at=NOW,
    )
    interface = QueryInterfaceDefinition(
        tenant_id="tenant-a", interface_id="activity-query/test", interface_version="1",
        activity_types=["test"],
        fields=[{"name": "activity_id", "value_type": "string", "semantic": "活动标识", "nullable": False}],
        max_page_size=1000,
    )
    return ActivityQueryResult(
        tenant_id="tenant-a", case_id="case-a", source_identity="test",
        run_id="run-a", query_id="q-1", interface_definition=interface,
        execution_boundary=boundary, activities=activities, evidence_references=[],
    )


def _activity(kind, operation):
    base = {
        "tenant_id": "tenant-a", "activity_id": f"act-{kind}-{operation}",
        "observed_at": NOW, "ingested_at": NOW, "source_system": "test",
        "source_record_id": "r-1", "subject_refs": ["host:host-1"],
        "raw_record_ref": "raw-1", "normalizer_version": "1.0",
        "host_ref": "host-1",
    }
    if kind == "process":
        return ProcessActivity(
            **base, process_ref="process:host-1:1:100", pid=1, operation=operation,
        )
    if kind == "network":
        return NetworkActivity(
            **base, process_ref="process:host-1:1:100", operation=operation,
            direction="outbound",
        )
    if kind == "file":
        return FileActivity(
            **base, file_ref="file:host-1:a", operation=operation,
        )
    raise AssertionError(kind)


def _with_activities(state, activities):
    state.tool_ledger.query_results.append(_result(activities))
    return state


def _verdict(level, threat_type):
    return CandidateVerdict(
        level=level, threat_type=threat_type, summary="测试结论",
        supporting_refs=[], contradicting_refs=[], limitations=[],
    )


def test_collect_capabilities_observes_execution_network_and_file_change():
    state = _with_activities(_state(), [
        _activity("process", "execute"),
        _activity("network", "connect"),
        _activity("file", "write"),
    ])
    caps = collect_capabilities(state)
    assert caps == {"execution", "network", "file_change"}


def test_confirmed_backdoor_c2_kept_when_floor_met():
    state = _with_activities(_state(), [
        _activity("process", "execute"),
        _activity("network", "connect"),
    ])
    verdict = gate_verdict(state, _verdict(VerdictLevel.CONFIRMED_MALICIOUS, "backdoor_c2"))
    assert verdict.level == VerdictLevel.CONFIRMED_MALICIOUS
    assert verdict.limitations == []


def test_confirmed_backdoor_c2_downgraded_when_floor_unmet():
    state = _with_activities(_state(), [_activity("process", "execute")])
    verdict = gate_verdict(state, _verdict(VerdictLevel.CONFIRMED_MALICIOUS, "backdoor_c2"))
    assert verdict.level == VerdictLevel.SUSPICIOUS
    assert any("证据门槛未满足" in item for item in verdict.limitations)
    assert any("网络连接" in item for item in verdict.limitations)


def test_benign_verdict_never_upgraded_or_touched():
    state = _state()
    verdict = gate_verdict(state, _verdict(VerdictLevel.BENIGN, "unknown"))
    assert verdict.level == VerdictLevel.BENIGN
    assert verdict.limitations == []


def test_confirmed_unknown_threat_type_has_no_floor():
    state = _state()
    verdict = gate_verdict(state, _verdict(VerdictLevel.CONFIRMED_MALICIOUS, "unknown"))
    assert verdict.level == VerdictLevel.CONFIRMED_MALICIOUS
