from __future__ import annotations

import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..case_management import SQLiteInvestigationRuntimeStore
from ..contracts import (
    AuditEvent,
    InvestigationReport,
    InvestigationRun,
    InvestigationRunReadModel,
    OperationalEvent,
    ResponsePlan,
)
from ..data_foundation.adapters import SQLiteReferenceDataStore
from ..data_foundation.application import initialize_reference_demo
from .settings import AppSettings


_EVENT_TYPE = {
    "thinking": "model",
    "decision": "model",
    "repair": "validation",
    "validation": "validation",
    "report": "model",
    "response": "model",
    "tool": "tool",
    "evidence": "tool",
    "graph": "graph",
    "verdict": "graph",
    "result": "run",
    "complete": "run",
    "approval": "run",
    "run": "run",
    "error": "error",
    "model_input": "model",
    "model_output": "model",
    "tool_message": "model",
    "tool_error": "tool",
}

_STAGE_BY_KIND = {
    "run": "initializing",
    "graph": "investigating",
    "thinking": "investigating",
    "decision": "investigating",
    "tool": "investigating",
    "evidence": "investigating",
    "verdict": "judgment",
    "report": "reporting",
    "response": "response_advisory",
    "approval": "approval",
    "result": "publishing",
    "complete": "published",
}


class DemoRunService:
    """Background demo executor whose externally visible facts are persisted in SQLite."""

    tenant_id = "demo"

    def __init__(
        self,
        settings: AppSettings,
        *,
        project_root: Path,
        runtime_store: SQLiteInvestigationRuntimeStore | None = None,
    ):
        self.settings = settings
        self.project_root = project_root
        self.runtime_store = runtime_store or SQLiteInvestigationRuntimeStore(
            settings.demo.runtime_store_path
        )

    def start(self, dataset_id: str, profile_id: str) -> str:
        case_id = self._resolve_case(dataset_id, profile_id)
        run_id = f"ai-{uuid.uuid4().hex[:12]}"
        run = InvestigationRun(
            tenant_id=self.tenant_id,
            case_id=case_id,
            source_identity="persistent-demo-run-service",
            run_id=run_id,
            status="queued",
            stage="queued",
            graph_thread_id=f"{self.tenant_id}/{case_id}/{run_id}",
            started_at=datetime.now(timezone.utc),
        )
        self.runtime_store.create_run(run, dataset_id=dataset_id, profile_id=profile_id)
        self._audit(
            run_id,
            case_id,
            "run_created",
            "investigation_run",
            run_id,
            result_summary="已创建调查运行",
        )
        threading.Thread(
            target=self._execute,
            args=(run_id, dataset_id, profile_id),
            name=f"demo-run-{run_id}",
            daemon=True,
        ).start()
        return run_id

    def get_investigation(self, run_id: str) -> InvestigationRunReadModel | None:
        run = self.runtime_store.get_run(self.tenant_id, run_id)
        if run is None:
            return None
        metadata = self.runtime_store.get_run_metadata(self.tenant_id, run_id) or {}
        report_payload = self.runtime_store.get_artifact(
            self.tenant_id, run_id, "investigation_report"
        )
        response_payload = self.runtime_store.get_artifact(
            self.tenant_id, run_id, "response_plan"
        )
        return InvestigationRunReadModel(
            run=run,
            reference_dataset_id=str(metadata.get("dataset_id") or ""),
            profile_id=str(metadata.get("profile_id") or ""),
            events=self.runtime_store.list_operational_events(self.tenant_id, run_id),
            investigation_report=(
                InvestigationReport.model_validate(report_payload)
                if report_payload is not None
                else None
            ),
            response_plan=(
                ResponsePlan.model_validate(response_payload)
                if response_payload is not None
                else None
            ),
        )

    def _resolve_case(self, dataset_id: str, profile_id: str) -> str:
        store = SQLiteReferenceDataStore(self.settings.demo.data_store_path)
        try:
            metadata = initialize_reference_demo(store, project_root=self.project_root)
            if dataset_id not in metadata:
                raise KeyError(f"Unknown reference dataset: {dataset_id}")
            profiles = store.list_profiles(dataset_id, self.settings.demo.dataset_version)
            if profile_id not in {item.profile_id for item in profiles}:
                raise KeyError(f"Unknown data profile: {profile_id}")
            row = store.connection.execute(
                "SELECT case_id FROM cases WHERE dataset_id=? AND dataset_version=?",
                (dataset_id, self.settings.demo.dataset_version),
            ).fetchone()
            if row is None:
                raise KeyError(f"Reference dataset has no case: {dataset_id}")
            return str(row["case_id"])
        finally:
            store.close()

    def _execute(self, run_id: str, dataset_id: str, profile_id: str) -> None:
        from .demo import run_demo_profile

        run = self._required_run(run_id).model_copy(
            update={"status": "running", "stage": "initializing"}
        )
        self.runtime_store.update_run(run)
        self._emit(run_id, "run", "正在初始化 AI 调查运行")
        store = SQLiteReferenceDataStore(self.settings.demo.data_store_path)
        try:
            initialize_reference_demo(store, project_root=self.project_root)

            def emit(
                kind: str, message: str, details: dict[str, Any] | None = None
            ) -> None:
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
            self.runtime_store.put_artifact(
                self.tenant_id, run_id, "demo_result", result.model_dump(mode="json")
            )
            if result.investigation_report is not None:
                self.runtime_store.put_artifact(
                    self.tenant_id,
                    run_id,
                    "investigation_report",
                    result.investigation_report.model_dump(mode="json"),
                )
            if result.case.response_plan is not None:
                self.runtime_store.put_artifact(
                    self.tenant_id,
                    run_id,
                    "response_plan",
                    result.case.response_plan.model_dump(mode="json"),
                )
            completed = self._required_run(run_id).model_copy(
                update={
                    "status": "completed",
                    "stage": "published",
                    "completed_at": datetime.now(timezone.utc),
                    "report_id": (
                        result.investigation_report.report_id
                        if result.investigation_report is not None
                        else None
                    ),
                }
            )
            self.runtime_store.update_run(completed)
            self._audit(
                run_id,
                completed.case_id,
                "run_completed",
                "investigation_run",
                run_id,
                input_refs=(
                    [result.investigation_report.report_id]
                    if result.investigation_report is not None
                    else []
                ),
                result_summary="调查报告与处置建议已发布",
            )
            self._emit(run_id, "complete", "AI 研判与处置建议已完成")
        except Exception as error:
            current = self._required_run(run_id)
            failed = current.model_copy(
                update={
                    "status": "failed",
                    "completed_at": datetime.now(timezone.utc),
                    "error_type": type(error).__name__,
                }
            )
            self.runtime_store.update_run(failed)
            self._audit(
                run_id,
                failed.case_id,
                "run_failed",
                "investigation_run",
                run_id,
                result_summary=f"运行失败：{type(error).__name__}",
            )
            self._emit(
                run_id,
                "error",
                "运行失败；请检查模型服务、结构化输出或调查预算",
                {
                    "error_type": type(error).__name__,
                    "error_message": str(error),
                    "exception_repr": repr(error),
                },
            )
        finally:
            store.close()

    def _emit(
        self,
        run_id: str,
        kind: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        run = self._required_run(run_id)
        stage = _STAGE_BY_KIND.get(kind, run.stage)
        if stage != run.stage:
            run = run.model_copy(update={"stage": stage})
            self.runtime_store.update_run(run)
        sequence = self.runtime_store.next_operational_sequence(self.tenant_id, run_id)
        safe_details = self._safe_details(details or {})
        duration_ms = safe_details.pop("duration_ms", None)
        token_usage = safe_details.pop("token_usage", {})
        retry_count = safe_details.pop("retry_count", 0)
        event_type = _EVENT_TYPE.get(kind, "run")
        if event_type == "model":
            model = (
                self.settings.response_model
                if kind == "response"
                else self.settings.judgment_model
            )
            safe_details = {
                **safe_details,
                "provider": urlparse(model.base_url).hostname or "openai-compatible",
                "model": model.model_name or "not-configured",
                "prompt_version": (
                    "response-advisory/1.0"
                    if kind == "response"
                    else "judgment/1.0"
                ),
            }
        event = OperationalEvent(
            tenant_id=self.tenant_id,
            case_id=run.case_id,
            source_identity="persistent-demo-run-service",
            run_id=run_id,
            event_id=f"event-{run_id}-{sequence:05d}",
            sequence=sequence,
            event_type=event_type,
            stage=stage,
            duration_ms=duration_ms,
            token_usage=token_usage,
            retry_count=retry_count,
            details={"kind": kind, "message": message, **safe_details},
            correlation_id=run.graph_thread_id or run_id,
        )
        self.runtime_store.append_operational_event(event)
        if kind in {"tool", "report", "approval"}:
            action = {
                "tool": "tool_invoked",
                "report": "report_published",
                "approval": "demo_approval_decided",
            }[kind]
            resource_ref = str(
                safe_details.get("query_id")
                or safe_details.get("report_id")
                or safe_details.get("request_ref")
                or run_id
            )
            self._audit(
                run_id,
                run.case_id,
                action,
                kind,
                resource_ref,
                input_refs=list(safe_details.get("evidence_ids") or []),
                result_summary=message,
                scope_snapshot=safe_details.get("scope") or {},
            )

    def _audit(
        self,
        run_id: str,
        case_id: str,
        action: str,
        resource_type: str,
        resource_ref: str,
        *,
        input_refs: list[str] | None = None,
        result_summary: str,
        scope_snapshot: dict[str, Any] | None = None,
    ) -> None:
        sequence = self.runtime_store.next_audit_sequence(self.tenant_id, run_id)
        run = self.runtime_store.get_run(self.tenant_id, run_id)
        self.runtime_store.append_audit_event(
            AuditEvent(
                tenant_id=self.tenant_id,
                case_id=case_id,
                source_identity="persistent-demo-run-service",
                run_id=run_id,
                audit_id=f"audit-{run_id}-{sequence:05d}",
                sequence=sequence,
                action=action,
                resource_type=resource_type,
                resource_ref=resource_ref,
                scope_snapshot=self._safe_details(scope_snapshot or {}),
                input_refs=input_refs or [],
                result_summary=result_summary,
                correlation_id=(run.graph_thread_id if run else None) or run_id,
            )
        )

    def _required_run(self, run_id: str) -> InvestigationRun:
        run = self.runtime_store.get_run(self.tenant_id, run_id)
        if run is None:
            raise KeyError(f"Unknown investigation run: {run_id}")
        return run

    @staticmethod
    def _safe_details(value: Any) -> Any:
        forbidden = {
            "apikey",
            "authorization",
            "password",
            "secret",
            "prompt",
        }
        if isinstance(value, dict):
            return {
                str(key): DemoRunService._safe_details(item)
                for key, item in value.items()
                if re.sub(r"[^a-z0-9]", "", str(key).lower()) not in forbidden
            }
        if isinstance(value, (list, tuple)):
            return [DemoRunService._safe_details(item) for item in value]
        return value
