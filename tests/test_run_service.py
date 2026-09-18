"""Feature 17 step 01 — RunService lifecycle over the ExecutionPort."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from fastapi.testclient import TestClient

from threat_agent.bootstrap.settings import AppSettings
from threat_agent.case_management import (
    RunService,
    RunServiceConfig,
    SQLiteInvestigationRuntimeStore,
)
from threat_agent.contracts import (
    InvestigationRun,
    RunExecutionOutcome,
    RunExecutionRequest,
)
from threat_agent.presentation import InMemoryCaseReadStore, InMemoryDemoComparisonStore
from threat_agent.presentation.api.routes import create_app

TENANT = "demo"


class FakeExecution:
    def __init__(
        self,
        *,
        outcome: RunExecutionOutcome | None = None,
        error: Exception | None = None,
        delay: float = 0.0,
    ):
        self.outcome = outcome
        self.error = error
        self.delay = delay
        self.calls: list[RunExecutionRequest] = []
        self.spans: list[tuple[float, float]] = []
        self._span_lock = threading.Lock()

    def execute(self, request: RunExecutionRequest, *, emit):
        emit("graph", "调查流程启动", {"node": "intake", "orchestration": "framework_middleware"})
        with self._span_lock:
            started = time.monotonic()
        if self.delay:
            time.sleep(self.delay)
        self.calls.append(request)
        with self._span_lock:
            self.spans.append((started, time.monotonic()))
        if self.error is not None:
            raise self.error
        return self.outcome or RunExecutionOutcome(
            artifacts={"demo_result": {"ok": True}}, result_summary="案件处理完成：测试"
        )


def _service(tmp_path: Path, execution: FakeExecution) -> RunService:
    store = SQLiteInvestigationRuntimeStore(tmp_path / "runtime.sqlite")
    return RunService(
        RunServiceConfig(tenant_id=TENANT),
        execution=execution,
        resolve_case=lambda dataset_id, profile_id: "case-resolved",
        runtime_store=store,
    )


def _await_terminal(service: RunService, run_id: str, timeout: float = 10.0, tenant: str = TENANT):
    """Wait until the terminal marker event (complete/error) is persisted —
    the run row flips status slightly before the trailing audit and event
    land, so the event stream is the authoritative completion signal."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = service.runtime_store.get_run(tenant, run_id)
        assert run is not None
        kinds = [
            event.details.get("kind")
            for event in service.runtime_store.list_operational_events(tenant, run_id)
        ]
        if "complete" in kinds:
            assert run.status == "completed"
            return run
        if "error" in kinds:
            assert run.status == "failed"
            return run
        time.sleep(0.02)
    raise AssertionError(f"run {run_id} did not reach a terminal state")


def test_run_lifecycle_persists_events_artifacts_and_terminal_state(tmp_path: Path):
    execution = FakeExecution(
        outcome=RunExecutionOutcome(
            artifacts={
                "demo_result": {"ok": True},
                "investigation_report": {"pending": True},
            },
            report_id="report-1",
            result_summary="案件处理完成：确认恶意",
        )
    )
    service = _service(tmp_path, execution)
    try:
        run_id = service.start("dataset-a", "profile-l3")
        run = _await_terminal(service, run_id)
        assert execution.calls[0].case_id == "case-resolved"
        assert execution.calls[0].run_id == run_id
        assert run.status == "completed"
        assert run.stage == "published"
        assert run.report_id == "report-1"
        assert service.runtime_store.get_artifact(TENANT, run_id, "demo_result") == {"ok": True}
        kinds = [
            event.details.get("kind")
            for event in service.runtime_store.list_operational_events(TENANT, run_id)
        ]
        assert kinds[0] == "run" and kinds[-1] == "complete"
        audit_actions = [
            item.action for item in service.runtime_store.list_audit_events(TENANT, run_id)
        ]
        assert audit_actions[0] == "run_created"
        assert audit_actions[-1] == "run_completed"
    finally:
        service.close()


def test_execution_failure_marks_run_failed_with_error_type(tmp_path: Path):
    service = _service(tmp_path, FakeExecution(error=RuntimeError("模型不可用")))
    try:
        run_id = service.start("dataset-a", "profile-l3")
        run = _await_terminal(service, run_id)
        assert run.status == "failed"
        assert run.error_type == "RuntimeError"
        error_events = [
            event
            for event in service.runtime_store.list_operational_events(TENANT, run_id)
            if event.event_type == "error"
        ]
        assert error_events and error_events[0].details["error_type"] == "RuntimeError"
    finally:
        service.close()


def test_recover_orphans_marks_only_active_runs_failed(tmp_path: Path):
    service = _service(tmp_path, FakeExecution())
    store = service.runtime_store
    try:
        from datetime import datetime, timezone

        for run_id, status, stage in (
            ("run-active", "running", "investigating"),
            ("run-queued", "queued", "queued"),
            ("run-done", "completed", "published"),
        ):
            from datetime import datetime, timezone

            store.create_run(
                InvestigationRun(
                    tenant_id=TENANT,
                    case_id="case-a",
                    source_identity="test",
                    run_id=run_id,
                    status=status,
                    stage=stage,
                    graph_thread_id=f"{TENANT}/case-a/{run_id}",
                    started_at=datetime.now(timezone.utc),
                ),
                dataset_id="dataset-a",
                profile_id="profile-a",
            )
        recovered = service.recover_orphans()
        assert sorted(recovered) == ["run-active", "run-queued"]
        assert store.get_run(TENANT, "run-active").error_type == "InterruptedRun"
        assert store.get_run(TENANT, "run-queued").status == "failed"
        assert store.get_run(TENANT, "run-done").status == "completed"
        audit_actions = {
            item.action
            for item in store.list_audit_events(TENANT, "run-active")
        }
        assert "run_interrupted" in audit_actions
    finally:
        service.close()


def test_replay_starts_fresh_run_for_same_source(tmp_path: Path):
    execution = FakeExecution()
    service = _service(tmp_path, execution)
    try:
        original = service.start("dataset-a", "profile-l3")
        _await_terminal(service, original)
        replayed = service.replay(original)
        assert replayed != original
        replay_run = _await_terminal(service, replayed)
        assert replay_run.case_id == "case-resolved"
        replay_audits = service.runtime_store.list_audit_events(TENANT, replayed)
        replay_action = next(item for item in replay_audits if item.action == "run_replayed")
        assert replay_action.resource_ref == original
        original_run = service.runtime_store.get_run(TENANT, original)
        assert original_run.status == "completed"
    finally:
        service.close()


def test_concurrent_starts_serialize_into_one_execution_slot(tmp_path: Path):
    execution = FakeExecution(delay=0.15)
    service = _service(tmp_path, execution)
    try:
        first = service.start("dataset-a", "profile-l3")
        second = service.start("dataset-a", "profile-l2")
        _await_terminal(service, first)
        _await_terminal(service, second)
        assert len(execution.spans) == 2
        execution.spans.sort()
        (first_start, first_end), (second_start, second_end) = execution.spans
        assert second_start >= first_end, "execution must not overlap: single writer slot"
    finally:
        service.close()


def test_workbench_api_lists_and_serves_runs(tmp_path: Path):
    settings = AppSettings.load(
        environ={"THREAT_AGENT_MODE": "deterministic"},
        env_file=tmp_path / "missing.env",
    )
    execution = FakeExecution()
    store = SQLiteInvestigationRuntimeStore(tmp_path / "runtime.sqlite")
    service = RunService(
        RunServiceConfig(tenant_id=settings.application.default_tenant),
        execution=execution,
        resolve_case=lambda dataset_id, profile_id: "case-resolved",
        runtime_store=store,
    )
    try:
        app = create_app(
            InMemoryCaseReadStore(), InMemoryDemoComparisonStore({}), service
        )
        client = TestClient(app)
        started = client.post(
            "/api/investigations",
            json={"reference_dataset_id": "dataset-a", "profile_id": "profile-l3"},
        )
        assert started.status_code == 202
        run_id = started.json()["run_id"]
        tenant = settings.application.default_tenant
        _await_terminal(service, run_id, tenant=tenant)

        listed = client.get("/api/runs")
        assert listed.status_code == 200
        payload = listed.json()["runs"]
        assert payload and payload[0]["run"]["run_id"] == run_id
        assert payload[0]["dataset_id"] == "dataset-a"

        detail = client.get(f"/api/runs/{run_id}")
        assert detail.status_code == 200
        assert detail.json()["run"]["status"] == "completed"

        page = client.get("/workbench")
        assert page.status_code == 200
        # The interactive workbench renders runs client-side from /api/runs;
        # the shell only carries the page identity and the scripts.
        assert "调查中心" in page.text
        assert "/api/runs" in page.text
    finally:
        service.close()
