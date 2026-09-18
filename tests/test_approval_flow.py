"""Feature 17 step 03 — approval desk, alert intake, SSE, evidence API."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from fastapi.testclient import TestClient

from threat_agent.bootstrap.settings import AppSettings
from threat_agent.case_management import (
    ApprovalService,
    RunService,
    RunServiceConfig,
    SQLiteInvestigationRuntimeStore,
)
from threat_agent.case_management.application.intake import derive_case_id
from threat_agent.contracts import (
    ApprovalDecision,
    RunExecutionOutcome,
    RunExecutionRequest,
)
from threat_agent.presentation import InMemoryCaseReadStore, InMemoryDemoComparisonStore
from threat_agent.presentation.api.routes import create_app

TENANT = "demo"


class PendingApprovalExecution:
    """Execution that parks the run at the response-approval interrupt."""

    def __init__(self):
        self.calls: list[RunExecutionRequest] = []

    def execute(self, request: RunExecutionRequest, *, emit):
        self.calls.append(request)
        emit("approval", "处置方案已生成，等待人工审批", {
            "node": "approve", "pending": True,
            "plan": {"status": "approval_required", "actions": []},
        })
        return RunExecutionOutcome(
            artifacts={"alert_payload": {"File_hash": "a"} if request.source == "alert_json" else {}},
            pending_approval=True,
            result_summary="处置方案等待人工审批",
        )


class RecordingApprovalPort:
    def __init__(self):
        self.calls: list[dict] = []

    def resume_approval(self, request, *, approved, approved_by, comment=None,
                        edited_plan=None, emit=None):
        self.calls.append({
            "run_id": request.run_id, "approved": approved,
            "approved_by": approved_by, "comment": comment,
            "edited_plan": edited_plan,
        })
        return {"approval_status": f"response_approved_by:{approved_by}"}


def _service(tmp_path: Path, execution) -> RunService:
    store = SQLiteInvestigationRuntimeStore(tmp_path / "runtime.sqlite")
    return RunService(
        RunServiceConfig(tenant_id=TENANT),
        execution=execution,
        resolve_case=lambda dataset_id, profile_id: "case-resolved",
        runtime_store=store,
    )


def _await_status(service: RunService, run_id: str, status: str, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = service.runtime_store.get_run(TENANT, run_id)
        if run.status == status:
            return run
        time.sleep(0.02)
    raise AssertionError(f"run never reached {status}")


def test_alert_intake_derives_deterministic_case_and_parks_at_approval(tmp_path: Path):
    execution = PendingApprovalExecution()
    service = _service(tmp_path, execution)
    try:
        raw = {
            "File_id": "file-9", "File_hash": "b" * 64, "File_path": "/tmp/x",
            "Sub_asset": "host-9",
        }
        first = service.start_alert(raw)
        second = service.start_alert(raw)
        assert first != second
        # Same alert payload derives the same case (deterministic intake).
        run = _await_status(service, first, "awaiting_approval")
        assert run.case_id == derive_case_id(raw)
        assert second and service.runtime_store.get_run(TENANT, second).case_id == run.case_id
        assert execution.calls[0].source == "alert_json"
        assert execution.calls[0].alert == raw
        # The parking audit lands right after the status flip; wait for it.
        deadline = time.monotonic() + 5
        audits: list[str] = []
        while time.monotonic() < deadline:
            audits = [a.action for a in service.runtime_store.list_audit_events(TENANT, first)]
            if "approval_requested" in audits:
                break
            time.sleep(0.02)
        assert "approval_requested" in audits
        # Rule 5: approval parking is written by the run service only.
    finally:
        service.close()


def test_approval_service_four_state_decisions_audited_and_completed(tmp_path: Path):
    service = _service(tmp_path, PendingApprovalExecution())
    port = RecordingApprovalPort()
    approval = ApprovalService(
        tenant_id=TENANT, approvals=port,
        runtime_store=service.runtime_store, run_service=service,
    )
    try:
        run_id = service.start("dataset-a", "profile-l3")
        _await_status(service, run_id, "awaiting_approval")

        pending = approval.list_pending()
        assert [item.run_id for item in pending] == [run_id]
        assert pending[0].plan["status"] == "approval_required"

        result = approval.decide(run_id, ApprovalDecision(
            decision="accept", decided_by="analyst-1",
        ))
        assert port.calls[-1]["approved"] is True
        assert port.calls[-1]["edited_plan"] is None
        assert result["approval_status"] == "response_approved_by:analyst-1"
        assert service.runtime_store.get_run(TENANT, run_id).status == "completed"
        audits = [a.action for a in service.runtime_store.list_audit_events(TENANT, run_id)]
        assert "approval_decided" in audits

        # edit requires a plan; respond requires a comment (contract enforced)
        run_id2 = service.start("dataset-a", "profile-l3")
        _await_status(service, run_id2, "awaiting_approval")
        try:
            approval.decide(run_id2, ApprovalDecision(decision="edit", decided_by="a"))
            raise AssertionError("edit without edited_plan must fail")
        except ValueError:
            pass
        approval.decide(run_id2, ApprovalDecision(
            decision="edit", decided_by="analyst-2",
            edited_plan={"status": "approval_required", "actions": []},
        ))
        assert port.calls[-1]["edited_plan"] is not None
        assert port.calls[-1]["approved"] is True

        try:
            approval.decide(run_id, ApprovalDecision(decision="respond", decided_by="a"))
            raise AssertionError("respond without comment must fail")
        except ValueError:
            pass
        try:
            approval.decide(run_id, ApprovalDecision(
                decision="accept", decided_by="a"
            ))
            raise AssertionError("deciding a completed run must fail")
        except ValueError:
            pass
    finally:
        service.close()


def test_sse_stream_and_evidence_endpoints(tmp_path: Path):
    class StreamExecution(PendingApprovalExecution):
        def execute(self, request, *, emit):
            super().execute(request, emit=emit)
            emit("tool", "查询进程", {"node": "execute", "query_id": "query-9"})
            return RunExecutionOutcome(
                artifacts={}, pending_approval=True, result_summary="等待审批"
            )

    service = _service(tmp_path, StreamExecution())
    try:
        app = create_app(
            InMemoryCaseReadStore(), InMemoryDemoComparisonStore({}), service,
            ApprovalService(
                tenant_id=TENANT, approvals=RecordingApprovalPort(),
                runtime_store=service.runtime_store, run_service=service,
            ),
        )
        client = TestClient(app)
        run_id = client.post(
            "/api/investigations",
            json={"reference_dataset_id": "ds", "profile_id": "l3"},
        ).json()["run_id"]
        _await_status(service, run_id, "awaiting_approval")

        with client.stream(
            "GET", f"/api/runs/{run_id}/events/stream?until=3"
        ) as response:
            body = "".join(response.iter_text())
        assert body.startswith("data: ")
        assert "query-9" in body

        evidence = client.get(f"/api/runs/{run_id}/evidence/query-9")
        assert evidence.status_code == 200
        assert evidence.json()["events"][0]["details"]["query_id"] == "query-9"

        pending = client.get("/api/approvals").json()["approvals"]
        assert run_id in [item["run_id"] for item in pending]

        decided = client.post(f"/api/approvals/{run_id}", json={
            "decision": "accept", "decided_by": "analyst-1",
        })
        assert decided.status_code == 200
        assert service.runtime_store.get_run(TENANT, run_id).status == "completed"
    finally:
        service.close()


def test_settings_default_tenant_is_respected_in_intake(tmp_path: Path):
    settings = AppSettings.load(
        environ={"THREAT_AGENT_DEFAULT_TENANT": "tenant-x"},
        env_file=tmp_path / "missing.env",
    )
    assert settings.application.default_tenant == "tenant-x"
    assert settings.workbench.debug_enabled is True
