"""Feature 17: debug surface over checkpoint history.

Read-only over run rows (architecture rule 5): this service never migrates
run state — it lists checkpoints, summarizes state, and replays/resumes
through the CheckpointPort, recording each debug action in the audit trail.
"""

from __future__ import annotations

from typing import Any

from ...contracts import CheckpointRef, DebugStateSummary, RunExecutionRequest
from ..adapters.runtime_store import SQLiteInvestigationRuntimeStore
from ..ports.checkpointing import CheckpointPort
from ..ports.execution import EventSink

_DEBUG_OPERATOR = "workbench-debug"


class DebugService:
    def __init__(
        self,
        *,
        tenant_id: str,
        checkpoints: CheckpointPort,
        runtime_store: SQLiteInvestigationRuntimeStore,
        emit: EventSink | None = None,
    ):
        self.tenant_id = tenant_id
        self.checkpoints = checkpoints
        self.runtime_store = runtime_store
        self.emit = emit or (lambda *_args, **_kwargs: None)

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

    def list_checkpoints(self, run_id: str) -> list[CheckpointRef]:
        return self.checkpoints.list_checkpoints(self._request(run_id))

    def state_summary(self, run_id: str, checkpoint_id: str) -> DebugStateSummary:
        return self.checkpoints.state_summary(self._request(run_id), checkpoint_id)

    def resume(
        self,
        run_id: str,
        checkpoint_id: str,
        *,
        value: dict[str, Any] | None = None,
        operator: str = _DEBUG_OPERATOR,
    ) -> dict[str, Any]:
        """Replay/resume one run from a checkpoint. The published artifacts and
        run row of record stay untouched; the replay only appends events
        (marked debug) and one audit record."""

        request = self._request(run_id)
        self.emit(
            run_id,
            "graph",
            f"调试恢复：从 checkpoint {checkpoint_id[:12]}… 重放",
            {"node": "debug", "debug_replay": True, "checkpoint_id": checkpoint_id},
        )

        def emit(kind: str, message: str, details: dict[str, Any] | None = None) -> None:
            self.emit(
                run_id,
                kind,
                message,
                {"debug_replay": True, "checkpoint_id": checkpoint_id, **(details or {})},
            )

        result = self.checkpoints.resume(request, checkpoint_id, value=value, emit=emit)
        sequence = self.runtime_store.next_audit_sequence(self.tenant_id, run_id)
        from ...contracts import AuditEvent

        run = self.runtime_store.get_run(self.tenant_id, run_id)
        self.runtime_store.append_audit_event(
            AuditEvent(
                tenant_id=self.tenant_id,
                case_id=request.case_id,
                source_identity="case-debug-service",
                run_id=run_id,
                audit_id=f"audit-{run_id}-{sequence:05d}",
                sequence=sequence,
                action="debug_resumed",
                resource_type="checkpoint",
                resource_ref=checkpoint_id,
                input_refs=[run_id],
                result_summary=(
                    f"调试恢复（{operator}）：从 checkpoint 重放，正式产物不受影响"
                ),
                correlation_id=(run.graph_thread_id if run else None) or run_id,
            )
        )
        return result
