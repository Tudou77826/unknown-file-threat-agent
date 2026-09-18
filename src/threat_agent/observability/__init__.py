"""Feature 17 — one-way observability sidecar.

Business modules never import this package; only the bootstrap composition
root wires a sink in. A sink failure degrades observation only — it must
never affect an investigation (degradation test pins this).
"""

from __future__ import annotations

from typing import Any, Protocol


class TraceSink(Protocol):
    def handler_for(
        self,
        *,
        tenant_id: str,
        case_id: str,
        run_id: str,
        session_key: str,
        tags: list[str],
    ) -> Any:
        """Return a LangChain callback handler for one run, or None."""
        ...

    def close(self) -> None: ...


class NullTraceSink:
    """Observation disabled or degraded: contribute nothing, fail nothing."""

    def handler_for(
        self,
        *,
        tenant_id: str,
        case_id: str,
        run_id: str,
        session_key: str,
        tags: list[str],
    ) -> None:
        return None

    def close(self) -> None:
        return None


def build_trace_sink(backend: str) -> TraceSink:
    """Resolve the configured sink; an unavailable backend degrades to Null."""

    if backend == "langfuse":
        try:
            from .adapters.langfuse_sink import LangfuseTraceSink

            return LangfuseTraceSink()
        except Exception:
            return NullTraceSink()
    return NullTraceSink()


__all__ = ["NullTraceSink", "TraceSink", "build_trace_sink"]
