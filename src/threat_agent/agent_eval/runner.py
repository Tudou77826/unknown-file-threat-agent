"""Concurrent execution engine (design.md §4.2).

Thread-pool scheduling over an EvalTask protocol; the kernel owns status
classification, idempotent resume (skip finished run_ids), ``--fresh``
resampling (bump the epoch cursor), per-worker isolated workdirs and
artifact/run-record persistence. It knows nothing about providers, models or
business semantics — those live entirely in the injected EvalTask.
"""

from __future__ import annotations

import json
import shutil
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from pydantic import Field

from ._base import StrictModel
from .core import Case, EvalTask, RunRecord, build_run_id
from .rate_limit import RateLimiter


class RunnerConfig(StrictModel):
    workers: int = Field(default=4, ge=1, le=64)
    epochs: int = Field(default=1, ge=1, le=25, description="pass^k 的 k")
    fresh: bool = Field(default=False, description="True 时忽略已完成记录全部重采样")
    timeout_seconds: float = Field(default=1800.0, gt=0)


class RunResult(StrictModel):
    record: RunRecord
    workdir: str


class Runner:
    """Executes (case × epoch) pairs to completion, resuming around finished
    runs. ``on_event`` receives progress callables-friendly dicts so a CLI can
    stream progress without coupling the kernel to any reporter."""

    def __init__(
        self,
        task: EvalTask,
        *,
        output_dir: Path,
        config: RunnerConfig,
        limiter: RateLimiter | None = None,
        on_event: Callable[[dict], None] | None = None,
    ):
        self.task = task
        self.output_dir = Path(output_dir)
        self.config = config
        self.limiter = limiter
        self.on_event = on_event or (lambda _event: None)

    # -- public API ----------------------------------------------------------

    def run_suite(self, cases: list[Case]) -> list[RunResult]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        pending: list[tuple[Case, int, str]] = []
        results: list[RunResult] = []
        for case in cases:
            for epoch in range(1, self.config.epochs + 1):
                run_id = build_run_id(case.case_id, {}, epoch)
                path = self._record_path(run_id)
                # 幂等续跑只跳过 ok 的 run：error/timeout 属于未完成，补跑。
                if not self.config.fresh and path.exists():
                    record = RunRecord.model_validate_json(path.read_text(encoding="utf-8"))
                    if record.status == "ok":
                        self.on_event({"type": "skip", "run_id": run_id})
                        results.append(RunResult(record=record, workdir=str(self._workdir(run_id))))
                        continue
                pending.append((case, epoch, run_id))

        if pending:
            workers = min(self.config.workers, len(pending))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(self._execute_one, case, epoch, run_id): run_id
                    for case, epoch, run_id in pending
                }
                for future in as_completed(futures):
                    results.append(future.result())
        results.sort(key=lambda item: (item.record.case_ref, item.record.run_id))
        return results

    # -- internals -----------------------------------------------------------

    def _workdir(self, run_id: str) -> Path:
        return self.output_dir / "runs" / run_id.replace("#", "_").replace(":", "_")

    def _record_path(self, run_id: str) -> Path:
        return self._workdir(run_id) / "run_record.json"

    def _execute_one(self, case: Case, epoch: int, run_id: str) -> RunResult:
        workdir = self._workdir(run_id)
        # 幂等续跑的失败重试：清掉上次的半成品目录
        if workdir.exists():
            shutil.rmtree(workdir)
        (workdir / "artifacts").mkdir(parents=True, exist_ok=True)

        started = time.monotonic()
        if self.limiter is not None:
            self.limiter.acquire(tokens=0)
        status: str = "ok"
        error_message: str | None = None
        metrics: dict[str, float] = {}
        try:
            metrics = dict(
                self.task.run_case(case, epoch=epoch, workdir=workdir / "artifacts")
            )
            if self.limiter is not None:
                self.limiter.register_success()
        except _TimeoutMarker:
            status, error_message = "timeout", "task exceeded the configured timeout"
        except Exception as task_error:  # noqa: BLE001 — 单案失败被 Runner 隔离为该案 error
            status = "error"
            error_message = f"{type(task_error).__name__}: {task_error}"
            self.on_event({
                "type": "case_error",
                "run_id": run_id,
                "error": error_message,
                "traceback": traceback.format_exc(limit=6),
            })
        record = RunRecord(
            run_id=run_id,
            case_ref=case.case_id,
            config={"suite": case.suite, "tags": sorted(case.tags)},
            status=status,  # type: ignore[arg-type]
            metrics_raw=metrics,
            error=error_message,
            duration_seconds=round(time.monotonic() - started, 3),
        )
        self._record_path(run_id).write_text(record.model_dump_json(), encoding="utf-8")
        self.on_event({"type": "done", "run_id": run_id, "status": status})
        return RunResult(record=record, workdir=str(workdir))


class _TimeoutMarker(Exception):
    """Internal: raised by the timeout wrapper path (kept explicit so a task
    bug and a timeout never collapse into the same status)."""


def dump_json(path: Path, payload: dict) -> None:
    """Helper for TaskAdapters: persist one artifact deterministically."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
