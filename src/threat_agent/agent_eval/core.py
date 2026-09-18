"""Core contracts: the only vocabulary the kernel shares with consumers.

Case / RunRecord / Score / the three protocols follow design.md §4. The split
is Inspect AI's (dataset / run / score); Harbor's absorbed conventions show
up as named reward dimensions on Score, ``suite@version`` pinning on
SuiteManifest, and the artifact-first rule (scorers always read raw artifacts,
never pre-aggregated summaries).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import Field

from ._base import StrictModel

RunStatus = Literal["ok", "error", "timeout"]


class Case(StrictModel):
    """One exam question: input, environment description and ground truth.

    ``ground_truth`` keys are defined by the scorer set (design.md §4.1);
    ``environment`` describes fixtures the TaskAdapter must materialize into
    the worker workdir (seed data, data level, alert payload).
    """

    case_id: str = Field(min_length=1)
    suite: str = Field(min_length=1, description="suite@version 标识，进 git 版本化")
    task_input: dict[str, Any] = Field(default_factory=dict)
    environment: dict[str, Any] = Field(default_factory=dict)
    ground_truth: dict[str, Any] = Field(default_factory=dict)
    tags: frozenset[str] = Field(default_factory=frozenset)


class RunRecord(StrictModel):
    """One executed case. ``run_id`` is the idempotency key:
    ``{case_id}#{config_hash}#{epoch}``."""

    run_id: str = Field(min_length=1)
    case_ref: str = Field(min_length=1)
    config: dict[str, Any] = Field(default_factory=dict)
    status: RunStatus
    metrics_raw: dict[str, float] = Field(default_factory=dict)
    error: str | None = Field(default=None)
    # 相对 workdir 的产物路径；打分器只面对这些原始产物。
    artifacts: dict[str, str] = Field(default_factory=dict)
    duration_seconds: float = Field(default=0.0, ge=0)


class Score(StrictModel):
    """Harbor-style named reward dimensions (design.md §9.2): a scorer may
    return several dimensions plus a scalar total; ``notes`` carries the
    human-readable justification (evidence, matched ids, …)."""

    scorer: str = Field(min_length=1)
    dimensions: dict[str, float] = Field(default_factory=dict)
    total: float = Field(default=0.0)
    passed: bool | None = Field(default=None, description="None=该维度不适用判定")
    notes: list[str] = Field(default_factory=list)


class Scorer(Protocol):
    name: str

    def score(self, record: RunRecord, case: Case) -> Score: ...


class EvalTask(Protocol):
    """The only surface the Runner knows (design.md §4.2). Implementations
    write artifacts into ``workdir`` and return raw metrics; failures must be
    raised, not returned — the Runner owns status classification."""

    def run_case(self, case: Case, *, epoch: int, workdir: Path) -> dict[str, float]: ...


class SuiteManifest(StrictModel):
    """suite.toml 的模型：任务目录清单 + 版本钉住 + 默认维度权重。"""

    suite: str = Field(min_length=1, description="形如 secagent-evals@2026.09")
    case_ids: list[str] = Field(default_factory=list)
    weights: dict[str, float] = Field(default_factory=dict, description="维度 → 总分权重")
    default_epochs: int = Field(default=1, ge=1, le=25)


def config_hash(config: dict[str, Any]) -> str:
    """Stable short hash of a config dict — the idempotency key component."""

    canonical = json.dumps(config, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:12]


def build_run_id(case_id: str, config: dict[str, Any], epoch: int) -> str:
    return f"{case_id}#{config_hash(config)}#{epoch}"
