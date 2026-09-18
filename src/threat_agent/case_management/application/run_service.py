"""Feature 17 — case run lifecycle service.

Owns every externally visible run fact: run rows, operational events, audit
records and artifacts, all persisted in the runtime store. Execution itself is
delegated to the ``ExecutionPort`` (implemented in the bootstrap composition
root); this service never assembles models, gateways or graphs.

Write-ownership invariants (architecture test rule 5):

- run rows are written only here;
- approval / debug services append audit records and never migrate run state;
- at most one execution thread runs at a time — a deliberate single-writer
  posture for the local SQLite stores (runtime store and checkpoint store).
"""

from __future__ import annotations

import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ...contracts import (
    AuditEvent,
    InvestigationReport,
    InvestigationRun,
    InvestigationRunReadModel,
    OperationalEvent,
    ResponsePlan,
    RunExecutionRequest,
    RunSummary,
    TrajectoryReadModel,
)
from ..adapters.runtime_store import SQLiteInvestigationRuntimeStore
from ..ports.execution import CaseResolver, EventSink, ExecutionPort
from .trajectory import build_trajectory

_EVENT_TYPE = {
    "thinking": "model",
    "decision": "model",
    "repair": "validation",
    "validation": "validation",
    "report": "model",
    "response": "model",
    "tool": "tool",
    "evidence": "tool",
    "round": "tool",
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
    "round": "investigating",
    "verdict": "judgment",
    "report": "reporting",
    "response": "response_advisory",
    "approval": "approval",
    "result": "publishing",
    "complete": "published",
}

# Default workflow node for each event kind. Ambiguous kinds (thinking, repair,
# approval) are overridden by an explicit `node` in the event details.
_NODE_BY_KIND = {
    "run": "intake",
    "graph": "intake",
    "decision": "plan",
    "tool_message": "validate",
    "tool": "execute",
    "tool_error": "execute",
    "round": "execute",
    "report": "compose",
    "validation": "gate",
    "verdict": "gate",
    "response": "advise",
    "result": "done",
    "complete": "done",
    "error": "error",
}

# model_input / model_output events carry a `phase`; map it to a workflow node.
_PHASE_TO_NODE = {
    "judgment_planning": "plan",
    "judgment_report": "compose",
    "response_advisory": "advise",
}

_FORBIDDEN_DETAIL_KEYS = {
    "apikey",
    "authorization",
    "password",
    "secret",
    "prompt",
}


def redact_details(value: Any) -> Any:
    """Strip credential-shaped keys before anything reaches persistence."""

    if isinstance(value, dict):
        return {
            str(key): redact_details(item)
            for key, item in value.items()
            if re.sub(r"[^a-z0-9]", "", str(key).lower()) not in _FORBIDDEN_DETAIL_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [redact_details(item) for item in value]
    return value


class RunServiceConfig:
    """Plain values the service needs, resolved by the composition root from
    AppSettings (business modules never read process configuration)."""

    def __init__(
        self,
        *,
        tenant_id: str,
        judgment_provider: str = "",
        judgment_model: str = "",
        response_provider: str = "",
        response_model: str = "",
    ):
        self.tenant_id = tenant_id
        self.judgment_provider = judgment_provider
        self.judgment_model = judgment_model
        self.response_provider = response_provider
        self.response_model = response_model


class RunService:
    """Persistent run lifecycle over the execution port."""

    def __init__(
        self,
        config: RunServiceConfig,
        *,
        execution: ExecutionPort,
        resolve_case: CaseResolver,
        runtime_store: SQLiteInvestigationRuntimeStore | None = None,
        store_path: Path | None = None,
    ):
        self.config = config
        self.tenant_id = config.tenant_id
        self.execution = execution
        self.resolve_case = resolve_case
        if runtime_store is None:
            if store_path is None:
                raise ValueError("RunService requires runtime_store or store_path")
            runtime_store = SQLiteInvestigationRuntimeStore(store_path)
        self.runtime_store = runtime_store
        # Single execution slot: concurrent start/replay calls serialize here.
        self._execution_lock = threading.Lock()
        # Tool execution happens on worker threads (create_agent); event
        # emission from those threads must not race the sequence allocation.
        self._emit_lock = threading.Lock()

    # ------------------------------------------------------------------ API

    def start(self, dataset_id: str, profile_id: str) -> str:
        case_id = self.resolve_case(dataset_id, profile_id)
        return self._launch(
            RunExecutionRequest(
                tenant_id=self.tenant_id,
                case_id=case_id,
                run_id=self._new_run_id(),
                source="reference_dataset",
                dataset_id=dataset_id,
                profile_id=profile_id,
            )
        )

    def start_alert(self, raw_alert: dict[str, Any]) -> str:
        """Create a case from a real alert payload (Feature 17 M2 intake)."""

        from .intake import derive_case_id

        return self._launch(
            RunExecutionRequest(
                tenant_id=self.tenant_id,
                case_id=derive_case_id(raw_alert),
                run_id=self._new_run_id(),
                source="alert_json",
                alert=raw_alert,
            )
        )

    def replay(self, run_id: str) -> str:
        """Start a fresh run for the same source; the original stays intact."""

        metadata = self.runtime_store.get_run_metadata(self.tenant_id, run_id)
        if metadata is None:
            raise KeyError(f"Unknown investigation run: {run_id}")
        new_run_id = self.start(metadata["dataset_id"], metadata["profile_id"])
        self._audit(
            new_run_id,
            self._required_run(new_run_id).case_id,
            "run_replayed",
            "investigation_run",
            run_id,
            input_refs=[run_id],
            result_summary=f"由历史运行 {run_id} 重放",
        )
        return new_run_id

    def recover_orphans(self) -> list[str]:
        """Mark queued/running runs as failed after a process restart.

        The run rows survive restarts; execution threads do not. Recovery is
        honest degradation: interrupted, never silently resumed.
        """

        recovered: list[str] = []
        for run, _dataset_id, _profile_id in self.runtime_store.list_runs(self.tenant_id):
            if run.status not in ("queued", "running"):
                continue
            failed = run.model_copy(
                update={
                    "status": "failed",
                    "error_type": "InterruptedRun",
                    "completed_at": datetime.now(timezone.utc),
                }
            )
            self.runtime_store.update_run(failed)
            self._audit(
                run.run_id,
                run.case_id,
                "run_interrupted",
                "investigation_run",
                run.run_id,
                result_summary="进程重启导致运行中断，已标记失败，可重放",
            )
            recovered.append(run.run_id)
        return recovered

    def list_runs(self) -> list[RunSummary]:
        return [
            RunSummary(run=run, dataset_id=dataset_id, profile_id=profile_id)
            for run, dataset_id, profile_id in self.runtime_store.list_runs(self.tenant_id)
        ]

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

    def get_trajectory(self, run_id: str) -> TrajectoryReadModel | None:
        run = self.runtime_store.get_run(self.tenant_id, run_id)
        if run is None:
            return None
        events = self.runtime_store.list_operational_events(self.tenant_id, run_id)
        return build_trajectory(events, run_id=run_id, case_id=run.case_id)

    def complete_after_approval(
        self,
        run_id: str,
        *,
        decided_by: str,
        approved: bool,
        comment: str | None = None,
    ) -> None:
        """Close an awaiting_approval run once the decision resumed the graph.
        Run-row writes stay exclusive to this service (rule 5)."""

        current = self._required_run(run_id)
        if current.status != "awaiting_approval":
            raise ValueError(f"Run {run_id} is not awaiting approval")
        completed = current.model_copy(
            update={
                "status": "completed",
                "stage": "advised",
                "completed_at": datetime.now(timezone.utc),
            }
        )
        self.runtime_store.update_run(completed)
        self._audit(
            run_id,
            completed.case_id,
            "approval_decided",
            "response_plan",
            run_id,
            input_refs=[decided_by],
            result_summary=(
                f"审批{'通过' if approved else '驳回'}（{decided_by}）"
                + (f"；意见：{comment}" if comment else "")
            ),
        )

    def list_audit(
        self, *, action: str | None = None, run_id: str | None = None, limit: int = 300
    ) -> list[AuditEvent]:
        if run_id:
            events = self.runtime_store.list_audit_events(self.tenant_id, run_id)
            if action:
                events = [item for item in events if item.action == action]
            return list(reversed(events))[:limit]
        return self.runtime_store.list_audit_global(self.tenant_id, action=action, limit=limit)

    def case_index(self) -> list[dict[str, Any]]:
        """Case-centric aggregation: one row per case across all its runs."""

        cases: dict[str, dict[str, Any]] = {}
        for run, dataset_id, profile_id in self.runtime_store.list_runs(self.tenant_id):
            entry = cases.setdefault(
                run.case_id,
                {"case_id": run.case_id, "runs": 0, "latest_status": run.status,
                 "latest_run_id": run.run_id, "verdict": None, "sources": set()},
            )
            entry["runs"] += 1
            entry["sources"].add(dataset_id or "alert_json")
        ordered = sorted(cases.values(), key=lambda item: item["latest_run_id"], reverse=True)
        for entry in ordered:
            entry["sources"] = sorted(entry["sources"])
            payload = self.runtime_store.get_artifact(
                self.tenant_id, entry["latest_run_id"], "investigation_report"
            )
            if payload and payload.get("verdict"):
                entry["verdict"] = payload["verdict"].get("level")
        return ordered

    def knowledge_stats(self) -> dict[str, Any]:
        """Cross-run knowledge consultation statistics (status / category)."""

        total = 0
        by_status: dict[str, int] = {}
        by_category: dict[str, int] = {}
        recent: list[dict[str, Any]] = []
        for run, _ds, _profile in self.runtime_store.list_runs(self.tenant_id):
            for event in self.runtime_store.list_operational_events(self.tenant_id, run.run_id):
                details = event.details or {}
                if details.get("kind") != "knowledge":
                    continue
                total += 1
                status = str(details.get("status") or "unknown")
                by_status[status] = by_status.get(status, 0) + 1
                for source in details.get("sources") or []:
                    if isinstance(source, dict):
                        category = str(source.get("source_category") or "unknown")
                        by_category[category] = by_category.get(category, 0) + 1
                if len(recent) < 10:
                    recent.append({
                        "run_id": run.run_id,
                        "message": details.get("message"),
                        "status": status,
                    })
        return {"total": total, "by_status": by_status,
                "by_category": by_category, "recent": recent}

    def get_evidence(self, run_id: str, ref: str) -> list[OperationalEvent]:
        """Evidence drill-down: ledger events tied to one query/report ref."""

        matched = []
        for event in self.runtime_store.list_operational_events(self.tenant_id, run_id):
            details = event.details or {}
            refs = {str(details.get(key)) for key in ("query_id", "report_id", "request_ref")}
            refs.update(str(item) for item in details.get("evidence_ids") or [])
            if ref in refs:
                matched.append(event)
        return matched

    def close(self) -> None:
        self.runtime_store.close()

    # -------------------------------------------------------------- internals

    def _new_run_id(self) -> str:
        return f"ai-{uuid.uuid4().hex[:12]}"

    def _launch(self, request: RunExecutionRequest) -> str:
        run = InvestigationRun(
            tenant_id=self.tenant_id,
            case_id=request.case_id,
            source_identity="case-run-service",
            run_id=request.run_id,
            status="queued",
            stage="queued",
            graph_thread_id=f"{self.tenant_id}/{request.case_id}/{request.run_id}",
            started_at=datetime.now(timezone.utc),
        )
        self.runtime_store.create_run(
            run,
            dataset_id=request.dataset_id,
            profile_id=request.profile_id,
        )
        if request.source == "alert_json":
            # Persist the intake payload immediately so the event survives even
            # if execution fails before the executor persists artifacts.
            self.runtime_store.put_artifact(
                self.tenant_id, request.run_id, "alert_payload", request.alert
            )
        self._audit(
            request.run_id,
            request.case_id,
            "run_created",
            "investigation_run",
            request.run_id,
            result_summary="已创建调查运行",
        )
        threading.Thread(
            target=self._execute,
            args=(request,),
            name=f"case-run-{request.run_id}",
            daemon=True,
        ).start()
        return request.run_id

    def _execute(self, request: RunExecutionRequest) -> None:
        with self._execution_lock:
            self._execute_locked(request)

    def _execute_locked(self, request: RunExecutionRequest) -> None:
        run = self._required_run(request.run_id).model_copy(
            update={"status": "running", "stage": "initializing"}
        )
        self.runtime_store.update_run(run)
        self._emit(request.run_id, "run", "正在初始化 AI 调查运行")

        def emit(kind: str, message: str, details: dict[str, Any] | None = None) -> None:
            self._emit(request.run_id, kind, message, details)

        try:
            outcome = self.execution.execute(request, emit=emit)
        except Exception as error:
            self._fail(request.run_id, error)
            return
        for artifact_type, payload in outcome.artifacts.items():
            self.runtime_store.put_artifact(
                self.tenant_id, request.run_id, artifact_type, payload
            )
        if outcome.pending_approval:
            awaiting = self._required_run(request.run_id).model_copy(
                update={"status": "awaiting_approval", "stage": "approval"}
            )
            self.runtime_store.update_run(awaiting)
            self._audit(
                request.run_id,
                awaiting.case_id,
                "approval_requested",
                "response_plan",
                request.run_id,
                result_summary="处置方案已生成，等待人工审批",
            )
            return
        completed = self._required_run(request.run_id).model_copy(
            update={
                "status": "completed",
                "stage": "published",
                "completed_at": datetime.now(timezone.utc),
                "report_id": outcome.report_id,
            }
        )
        self.runtime_store.update_run(completed)
        self._audit(
            request.run_id,
            completed.case_id,
            "run_completed",
            "investigation_run",
            request.run_id,
            input_refs=[outcome.report_id] if outcome.report_id else [],
            result_summary=outcome.result_summary or "调查报告与处置建议已发布",
        )
        self._emit(request.run_id, "complete", "AI 研判与处置建议已完成")

    def _fail(self, run_id: str, error: Exception) -> None:
        import traceback

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
            result_summary=f"运行失败：{self._error_label(error)}",
        )
        self._emit(
            run_id,
            "error",
            "运行失败；请检查模型服务、结构化输出或调查预算",
            {
                "error_type": type(error).__name__,
                "error_message": str(error),
                "exception_repr": repr(error),
                "exception_traceback": traceback.format_exc()[-3500:],
            },
        )

    _ERROR_LABELS = {
        "InterfaceError": "数据存储访问冲突",
        "DataAccessError": "数据引用无效",
        "OutputParserException": "模型输出格式异常",
        "APITimeoutError": "模型服务超时",
        "APIConnectionError": "模型服务连接失败",
        "AnthropicInvalidRequestError": "模型服务拒绝请求",
        "BudgetExhausted": "调查预算耗尽",
    }

    @classmethod
    def _error_label(cls, error: Exception) -> str:
        return cls._ERROR_LABELS.get(type(error).__name__, type(error).__name__)

    def _required_run(self, run_id: str) -> InvestigationRun:
        run = self.runtime_store.get_run(self.tenant_id, run_id)
        if run is None:
            raise KeyError(f"Unknown investigation run: {run_id}")
        return run

    def _emit(
        self,
        run_id: str,
        kind: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self._emit_lock:
            self._emit_locked(run_id, kind, message, details)

    def _emit_locked(
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
        safe_details = redact_details(details or {})
        duration_ms = safe_details.pop("duration_ms", None)
        token_usage = safe_details.pop("token_usage", {})
        retry_count = safe_details.pop("retry_count", 0)
        explicit_node = safe_details.pop("node", None)
        phase = safe_details.get("phase")
        node = (
            (str(explicit_node) if explicit_node else "")
            or _PHASE_TO_NODE.get(phase, "")
            or _NODE_BY_KIND.get(kind, "")
            or stage
        )
        event_type = _EVENT_TYPE.get(kind, "run")
        if event_type == "model":
            if kind == "response":
                provider, model = self.config.response_provider, self.config.response_model
            else:
                provider, model = self.config.judgment_provider, self.config.judgment_model
            safe_details = {
                **safe_details,
                "provider": provider or "openai-compatible",
                "model": model or "not-configured",
                "prompt_version": (
                    "response-advisory/1.0" if kind == "response" else "judgment/1.0"
                ),
            }
        event = OperationalEvent(
            tenant_id=self.tenant_id,
            case_id=run.case_id,
            source_identity="case-run-service",
            run_id=run_id,
            event_id=f"event-{run_id}-{sequence:05d}",
            sequence=sequence,
            event_type=event_type,
            stage=stage,
            node=node,
            duration_ms=duration_ms,
            token_usage=token_usage,
            retry_count=retry_count,
            details={"kind": kind, "message": message, **safe_details},
            correlation_id=run.graph_thread_id or run_id,
        )
        self.runtime_store.append_operational_event(event)
        if kind in {"tool", "report", "approval", "knowledge"}:
            action = {
                "tool": "tool_invoked",
                "report": "report_published",
                "approval": "approval_decided",
                "knowledge": "knowledge_consulted",
            }[kind]
            resource_ref = str(
                safe_details.get("query_id")
                or safe_details.get("report_id")
                or safe_details.get("request_ref")
                or safe_details.get("consultation_id")
                or run_id
            )
            self._audit(
                run_id,
                run.case_id,
                action,
                kind,
                resource_ref,
                input_refs=list(
                    safe_details.get("evidence_ids")
                    or [
                        item["source_category"]
                        for item in safe_details.get("sources", [])
                        if isinstance(item, dict)
                    ]
                ),
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
                source_identity="case-run-service",
                run_id=run_id,
                audit_id=f"audit-{run_id}-{sequence:05d}",
                sequence=sequence,
                action=action,
                resource_type=resource_type,
                resource_ref=resource_ref,
                scope_snapshot=redact_details(scope_snapshot or {}),
                input_refs=input_refs or [],
                result_summary=result_summary,
                correlation_id=(run.graph_thread_id if run else None) or run_id,
            )
        )
