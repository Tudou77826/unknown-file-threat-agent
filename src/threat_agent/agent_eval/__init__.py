"""Reusable agent-evaluation kernel (Feature 16).

The package is self-contained like ``agent_middleware``: it must not import
any threat_agent business module (enforced by
test_architecture_dependencies.py) so it can be extracted into a standalone
distribution once validated. Business semantics enter through the three
protocols — CaseFactory, EvalTask and Scorer — and every primitive is shaped
after Inspect AI's task/run/score split with Harbor's absorbed conventions
(task directory, named reward dimensions, regrade, suite@version pinning).

Methodology references: design.md §4 (three-way split, pass^k) and §9
(Harbor absorption, 2026-09 survey).
"""

from __future__ import annotations

from .core import (
    Case,
    EvalTask,
    RunRecord,
    RunStatus,
    Score,
    Scorer,
    SuiteManifest,
    build_run_id,
    config_hash,
)
from .rate_limit import RateLimiter, RateLimitConfig
from .reporter import diff_baselines, render_markdown, summarize
from .runner import Runner, RunnerConfig
from .scoring import ScoreRunner

__all__ = [
    "Case",
    "EvalTask",
    "RateLimitConfig",
    "RateLimiter",
    "RunRecord",
    "RunStatus",
    "Runner",
    "RunnerConfig",
    "Score",
    "ScoreRunner",
    "Scorer",
    "SuiteManifest",
    "diff_baselines",
    "render_markdown",
    "summarize",
]
