from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..data_foundation.adapters import SQLiteReferenceDataStore
from ..data_foundation.application import initialize_reference_demo
from .settings import AppSettings


EventSink = Callable[[str, str, dict[str, Any] | None], None]


class DemoRunService:
    """In-process job runner for observable, user-triggered LLM demonstrations."""

    def __init__(self, settings: AppSettings, *, project_root: Path):
        self.settings = settings
        self.project_root = project_root
        self._jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def start(self, dataset_id: str, profile_id: str) -> str:
        run_id = f"ai-{uuid.uuid4().hex[:12]}"
        with self._lock:
            self._jobs[run_id] = {
                "run_id": run_id,
                "dataset_id": dataset_id,
                "profile_id": profile_id,
                "status": "queued",
                "events": [],
                "result": None,
                "error": None,
            }
        thread = threading.Thread(
            target=self._execute,
            args=(run_id, dataset_id, profile_id),
            name=f"demo-run-{run_id}",
            daemon=True,
        )
        thread.start()
        return run_id

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(run_id)
            if job is None:
                return None
            return {
                **job,
                "events": [dict(item) for item in job["events"]],
                "result": dict(job["result"]) if job["result"] else None,
            }

    def _emit(
        self,
        run_id: str,
        kind: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self._lock:
            job = self._jobs[run_id]
            job["events"].append(
                {
                    "sequence": len(job["events"]) + 1,
                    "at": datetime.now(timezone.utc).isoformat(),
                    "kind": kind,
                    "message": message,
                    "details": details or {},
                }
            )

    def _execute(self, run_id: str, dataset_id: str, profile_id: str) -> None:
        from .demo import run_demo_profile

        with self._lock:
            self._jobs[run_id]["status"] = "running"
        self._emit(run_id, "run", "正在初始化 AI 调查运行")
        store = SQLiteReferenceDataStore(self.settings.demo.data_store_path)
        try:
            metadata = initialize_reference_demo(store, project_root=self.project_root)
            if dataset_id not in metadata:
                raise KeyError(f"Unknown reference dataset: {dataset_id}")
            profile_ids = {
                item.profile_id
                for item in store.list_profiles(dataset_id, self.settings.demo.dataset_version)
            }
            if profile_id not in profile_ids:
                raise KeyError(f"Unknown data profile: {profile_id}")

            def emit(kind: str, message: str, details: dict[str, Any] | None = None) -> None:
                self._emit(run_id, kind, message, details)

            result = run_demo_profile(
                store,
                dataset_id=dataset_id,
                profile_id=profile_id,
                settings=self.settings,
                mode="llm",
                emit=emit,
                run_id=run_id,
            )
            with self._lock:
                self._jobs[run_id]["result"] = result.model_dump(mode="json")
                self._jobs[run_id]["status"] = "completed"
            self._emit(run_id, "complete", "AI 研判与处置建议已完成")
        except Exception as error:
            with self._lock:
                self._jobs[run_id]["status"] = "failed"
                self._jobs[run_id]["error"] = type(error).__name__
            self._emit(
                run_id,
                "error",
                "运行失败；请检查模型服务、结构化输出或调查预算",
                {"error_type": type(error).__name__},
            )
        finally:
            store.close()
