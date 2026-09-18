from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from threat_agent.case_management import (
    RunService,
    RunServiceConfig,
    SQLiteInvestigationRuntimeStore,
)
from threat_agent.bootstrap.settings import AppSettings
from threat_agent.contracts import AuditEvent, InvestigationRun, OperationalEvent


NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


def _settings(tmp_path: Path) -> AppSettings:
    return AppSettings.load(
        environ={
            "THREAT_AGENT_MODE": "deterministic",
            "THREAT_AGENT_DEFAULT_TENANT": "demo",
            "DEMO_DATA_STORE_PATH": str(tmp_path / "reference.sqlite"),
            "DEMO_RUNTIME_STORE_PATH": str(tmp_path / "runtime.sqlite"),
            "DEMO_DATASET_VERSION": "2026.08.1",
        },
        env_file=tmp_path / "missing.env",
    )


def _run(status="running") -> InvestigationRun:
    return InvestigationRun(
        tenant_id="demo", case_id="case-a", source_identity="test",
        run_id="run-a", status=status, stage=status,
        graph_thread_id="demo/case-a/run-a", started_at=NOW,
    )


def _service(settings: AppSettings, runtime_store) -> RunService:
    return RunService(
        RunServiceConfig(tenant_id=settings.application.default_tenant),
        execution=_NoExecution(),
        resolve_case=lambda dataset_id, profile_id: "case-a",
        runtime_store=runtime_store,
    )


class _NoExecution:
    """Execution must never be reached by lifecycle-only tests."""

    def execute(self, request, *, emit):  # pragma: no cover - guard
        raise AssertionError("execution must not run in this test")


def test_runtime_store_recovers_run_events_audit_and_artifacts_after_reopen(tmp_path: Path):
    path = tmp_path / "runtime.sqlite"
    first = SQLiteInvestigationRuntimeStore(path)
    first.create_run(_run(), dataset_id="dataset-a", profile_id="profile-a")
    first.append_operational_event(OperationalEvent(
        tenant_id="demo", case_id="case-a", source_identity="test", run_id="run-a",
        event_id="event-a", sequence=1, event_type="tool", stage="query",
        details={"kind": "tool", "message": "查询活动"}, correlation_id="corr-a",
    ))
    first.append_audit_event(AuditEvent(
        tenant_id="demo", case_id="case-a", source_identity="test", run_id="run-a",
        audit_id="audit-a", sequence=1, action="tool_invoked",
        resource_type="tool", resource_ref="query_activities",
        result_summary="查询完成", correlation_id="corr-a",
    ))
    first.put_artifact("demo", "run-a", "demo_result", {"ok": True})
    first.close()

    second = SQLiteInvestigationRuntimeStore(path)
    try:
        assert second.get_run("demo", "run-a").stage == "running"
        assert second.get_run_metadata("demo", "run-a") == {
            "dataset_id": "dataset-a", "profile_id": "profile-a"
        }
        assert [item.sequence for item in second.list_operational_events("demo", "run-a")] == [1]
        assert [item.action for item in second.list_audit_events("demo", "run-a")] == ["tool_invoked"]
        assert second.get_artifact("demo", "run-a", "demo_result") == {"ok": True}
        summaries = second.list_runs("demo")
        assert [item[0].run_id for item in summaries] == ["run-a"]
        assert summaries[0][1] == "dataset-a" and summaries[0][2] == "profile-a"
    finally:
        second.close()


def test_investigation_service_rebuilds_read_model_from_persistent_store(tmp_path: Path):
    settings = _settings(tmp_path)
    first_store = SQLiteInvestigationRuntimeStore(settings.demo.runtime_store_path)
    completed = _run("completed").model_copy(update={"completed_at": NOW})
    first_store.create_run(completed, dataset_id="dataset-a", profile_id="profile-a")
    first_store.append_operational_event(OperationalEvent(
        tenant_id="demo", case_id="case-a", source_identity="test", run_id="run-a",
        event_id="event-a", sequence=1, event_type="model", stage="thinking",
        details={"kind": "thinking", "message": "模型正在分析", "model": "fake"},
        correlation_id="demo/case-a/run-a",
    ))
    first_store.put_artifact("demo", "run-a", "demo_result", {"case": {"case_id": "case-a"}})
    first_store.close()

    restored = _service(
        settings, SQLiteInvestigationRuntimeStore(settings.demo.runtime_store_path)
    )
    try:
        formal = restored.get_investigation("run-a")
        assert formal.run.status == "completed"
        assert formal.reference_dataset_id == "dataset-a"
        assert formal.investigation_report is None
    finally:
        restored.runtime_store.close()


def test_persistent_events_are_ordered_correlated_and_scrub_sensitive_details(tmp_path: Path):
    settings = _settings(tmp_path)
    store = SQLiteInvestigationRuntimeStore(settings.demo.runtime_store_path)
    store.create_run(_run(), dataset_id="dataset-a", profile_id="profile-a")
    service = _service(settings, store)
    try:
        service._emit("run-a", "thinking", "模型分析", {
            "api_key": "must-not-persist", "prompt": "private prompt", "iteration": 1,
        })
        service._emit("run-a", "tool", "查询活动", {
            "query_id": "query-a", "authorization": "Bearer secret",
        })
        service._emit("run-a", "approval", "演示策略拒绝扩大范围", {
            "approved": False,
        })
        events = store.list_operational_events("demo", "run-a")
        audits = store.list_audit_events("demo", "run-a")
        assert [item.sequence for item in events] == [1, 2, 3]
        assert {item.correlation_id for item in events} == {"demo/case-a/run-a"}
        serialized = json.dumps(
            [item.model_dump(mode="json") for item in events + audits], ensure_ascii=False
        )
        assert "must-not-persist" not in serialized
        assert "private prompt" not in serialized
        assert "Bearer secret" not in serialized
        assert {item.action for item in audits} == {"tool_invoked", "approval_decided"}
    finally:
        store.close()


def test_failed_run_preserves_error_type_and_last_stage(tmp_path: Path):
    store = SQLiteInvestigationRuntimeStore(tmp_path / "runtime.sqlite")
    run = _run().model_copy(update={
        "status": "failed", "stage": "report", "error_type": "OutputParserException",
        "completed_at": NOW,
    })
    store.create_run(run, dataset_id="dataset-a", profile_id="profile-a")
    store.close()
    reopened = SQLiteInvestigationRuntimeStore(tmp_path / "runtime.sqlite")
    try:
        restored = reopened.get_run("demo", "run-a")
        assert restored.status == "failed"
        assert restored.stage == "report"
        assert restored.error_type == "OutputParserException"
    finally:
        reopened.close()
