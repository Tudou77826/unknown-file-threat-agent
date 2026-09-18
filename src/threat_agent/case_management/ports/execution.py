"""Feature 17: the run service delegates execution to this port.

The protocol lives with case governance (which owns run lifecycle); the
concrete implementation assembles the middleware runtime and lives in the
bootstrap composition root — the same dependency direction as
``middleware_bindings``. Identity is server-side: requests carry the run
identity resolved by the service, never payload-supplied identity.
"""

from __future__ import annotations

from typing import Any, Callable, Protocol

from ...contracts import RunExecutionOutcome, RunExecutionRequest

# (kind, message, details) — the operational event sink the executor reports to.
EventSink = Callable[[str, str, dict[str, Any] | None], None]


class ExecutionPort(Protocol):
    def execute(
        self, request: RunExecutionRequest, *, emit: EventSink
    ) -> RunExecutionOutcome: ...


CaseResolver = Callable[[str, str], str]
"""Resolve (dataset_id, profile_id) to the run's case_id. Implemented in the
composition root, which owns reference-data seeding."""
