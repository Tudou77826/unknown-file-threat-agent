"""Feature 17 M2: approval desk over the response-approval interrupt.

Read-only over run rows — completion after a decision is delegated to the
run service (rule 5). The decision itself resumes the paused graph through
the CheckpointPort; plan replacement and validation live in the graph node.
"""

from __future__ import annotations

from typing import Any, Protocol

from ...contracts import (
    ApprovalDecision,
    ApprovalRequestReadModel,
    RunExecutionRequest,
)
from ..adapters.runtime_store import SQLiteInvestigationRuntimeStore
from ..ports.execution import EventSink


class ApprovalPort(Protocol):
    def resume_approval(
        self,
        request: RunExecutionRequest,
        *,
        approved: bool,
        approved_by: str,
        comment: str | None = None,
        edited_plan: dict[str, Any] | None = None,
        emit: EventSink | None = None,
    ) -> dict[str, Any]: ...


class ApprovalService:
    def __init__(
        self,
        *,
        tenant_id: str,
        approvals: ApprovalPort,
        runtime_store: SQLiteInvestigationRuntimeStore,
        run_service: Any,
    ):
        self.tenant_id = tenant_id
        self.approvals = approvals
        self.runtime_store = runtime_store
        self.run_service = run_service

    def _request(self, run_id: str) -> RunExecutionRequest:
        run = self.runtime_store.get_run(self.tenant_id, run_id)
        if run is None:
            raise KeyError(f"Unknown investigation run: {run_id}")
        metadata = self.runtime_store.get_run_metadata(self.tenant_id, run_id) or {}
        return RunExecutionRequest(
            tenant_id=self.tenant_id,
            case_id=run.case_id,
            run_id=run_id,
            dataset_id=str(metadata.get("dataset_id") or ""),
            profile_id=str(metadata.get("profile_id") or ""),
        )

    def list_pending(self) -> list[ApprovalRequestReadModel]:
        pending: list[ApprovalRequestReadModel] = []
        for run, dataset_id, profile_id in self.runtime_store.list_runs(self.tenant_id):
            if run.status != "awaiting_approval":
                continue
            plan: dict[str, Any] = {}
            for event in reversed(self.runtime_store.list_operational_events(self.tenant_id, run.run_id)):
                details = event.details or {}
                if details.get("kind") == "approval" and details.get("pending"):
                    plan = details.get("plan") or {}
                    break
            pending.append(
                ApprovalRequestReadModel(
                    run_id=run.run_id,
                    case_id=run.case_id,
                    plan=plan,
                    requested_at=run.started_at,
                )
            )
        return pending

    def decide(self, run_id: str, decision: ApprovalDecision) -> dict[str, Any]:
        run = self.runtime_store.get_run(self.tenant_id, run_id)
        if run is None:
            raise KeyError(f"Unknown investigation run: {run_id}")
        if run.status != "awaiting_approval":
            raise ValueError(f"Run {run_id} is not awaiting approval")

        approved = decision.decision in ("accept", "edit")
        result = self.approvals.resume_approval(
            self._request(run_id),
            approved=approved,
            approved_by=decision.decided_by,
            comment=decision.comment,
            edited_plan=decision.edited_plan,
            emit=lambda kind, message, details=None: self.run_service._emit(
                run_id, kind, message,
                {"approval_kind": "response", "decision": decision.decision, **(details or {})},
            ),
        )
        self.run_service.complete_after_approval(
            run_id,
            decided_by=decision.decided_by,
            approved=approved,
            comment=decision.comment,
        )
        return result
