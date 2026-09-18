"""Feature 17: checkpoint access for the debug surface.

The port is defined beside run governance (which owns run identity); the
implementation lives in the bootstrap composition root, which rebuilds the
settings-derived graph for a finished run. Resume/replay always goes through
the CaseGraph entry methods — never around the authorization binding.
"""

from __future__ import annotations

from typing import Any, Protocol

from ...contracts import CheckpointRef, DebugStateSummary, RunExecutionRequest


class CheckpointPort(Protocol):
    def list_checkpoints(self, request: RunExecutionRequest) -> list[CheckpointRef]: ...

    def state_summary(
        self, request: RunExecutionRequest, checkpoint_id: str
    ) -> DebugStateSummary: ...

    def resume(
        self,
        request: RunExecutionRequest,
        checkpoint_id: str,
        *,
        value: dict[str, Any] | None,
        emit: Any = None,
    ) -> dict[str, Any]: ...

    def resume_approval(
        self,
        request: RunExecutionRequest,
        *,
        approved: bool,
        approved_by: str,
        comment: str | None = None,
        edited_plan: dict[str, Any] | None = None,
        emit: Any = None,
    ) -> dict[str, Any]:
        """Resume a pending response-approval interrupt (latest checkpoint)."""
        ...
