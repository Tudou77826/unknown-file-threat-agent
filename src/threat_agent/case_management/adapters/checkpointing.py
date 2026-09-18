from __future__ import annotations

import sqlite3
from pathlib import Path

from langgraph.checkpoint.memory import MemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.checkpoint.sqlite import SqliteSaver


def _serializer() -> JsonPlusSerializer:
    return JsonPlusSerializer(
        allowed_msgpack_modules=[
            ("threat_agent.contracts.evidence", "EvidenceStatus"),
            ("threat_agent.contracts.investigation", "VerdictLevel"),
            ("threat_agent.judgment.domain.models", "InvestigationState"),
            ("threat_agent.contracts.investigation", "JudgmentResult"),
            ("threat_agent.contracts.operations", "InvestigationReport"),
            ("threat_agent.contracts.response", "ResponsePlan"),
        ]
    )


def create_memory_checkpointer() -> MemorySaver:
    return MemorySaver(serde=_serializer())


def create_configured_checkpointer(backend: str, path: Path | str | None):
    """Resolve the settings-driven checkpointer: sqlite for durable runs
    (survives restarts, enables time-travel debug), memory for tests."""

    if backend == "sqlite":
        if path is None:
            raise ValueError("SQLite checkpoint backend requires a path")
        return create_sqlite_checkpointer(path)
    return create_memory_checkpointer()


def create_sqlite_checkpointer(path: Path | str) -> SqliteSaver:
    resolved = Path(path).resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(resolved), check_same_thread=False)
    return SqliteSaver(connection, serde=_serializer())
