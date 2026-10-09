"""Reusable agent middlewares built on the langchain 1.x middleware API.

The package is self-contained: it must not import any threat_agent
business module (enforced by test_architecture_dependencies.py) so it can
be extracted into a standalone distribution once validated. Business
semantics are injected through the protocols defined here.
"""

from __future__ import annotations

from .archive import (
    ARCHIVE_CONTEXT_TOOL,
    ArchiveMiddleware,
    ArchiveState,
    ArchiveStore,
    ArchiveToolInput,
)
from .boundary import (
    BoundaryMiddleware,
    BoundaryRejection,
    BoundaryState,
    BoundaryViolationError,
    ToolBoundary,
)
from .budget import (
    BudgetExhausted,
    BudgetMiddleware,
    BudgetPolicy,
    BudgetState,
    BudgetUsage,
    LimitsBudgetPolicy,
)
from .compaction import Reducer, ReducerMiddleware, UNREDUCED_ARTIFACT_KEY
from .events import EventSink, MiddlewareEvent, null_sink
from .hygiene import HistoryHygieneMiddleware
from .safety_net import SafetyNetMiddleware

__all__ = [
    "ARCHIVE_CONTEXT_TOOL",
    "ArchiveMiddleware",
    "ArchiveState",
    "ArchiveStore",
    "ArchiveToolInput",
    "BoundaryMiddleware",
    "BoundaryRejection",
    "BoundaryState",
    "BoundaryViolationError",
    "BudgetExhausted",
    "BudgetMiddleware",
    "BudgetPolicy",
    "BudgetState",
    "BudgetUsage",
    "EventSink",
    "HistoryHygieneMiddleware",
    "LimitsBudgetPolicy",
    "MiddlewareEvent",
    "Reducer",
    "ReducerMiddleware",
    "SafetyNetMiddleware",
    "ToolBoundary",
    "UNREDUCED_ARTIFACT_KEY",
    "null_sink",
]
