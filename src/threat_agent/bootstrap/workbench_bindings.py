"""Feature 17 step 01 — compose the run service with the reference-data
execution path.

This module is the composition-root adapter: it touches settings, the
reference data store and the middleware-runtime execution function, so it
lives in bootstrap by the dependency rules enforced in
test_architecture_dependencies.

- ``ReferenceProfileExecution`` implements the case_management ExecutionPort
  over ``run_demo_profile`` (the canonical middleware-runtime path); the run
  service only ever sees generic artifacts.
- ``reference_case_resolver`` seeds/validates the versioned reference store
  and resolves the run's case id — demo-specific knowledge that must not
  leak into case governance.
- ``build_run_service`` is the one factory the server entry uses.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..case_management import (
    ApprovalService,
    RunService,
    RunServiceConfig,
    initialize_state,
)
from ..case_management.ports.checkpointing import CheckpointPort
from ..contracts import (
    CheckpointRef,
    DebugStateSummary,
    RunExecutionOutcome,
    RunExecutionRequest,
)
from ..data_foundation.adapters import (
    SQLiteActivityStore,
    SQLiteInvestigationDataAdapter,
    SQLiteReferenceDataStore,
)
from ..data_foundation.application import initialize_reference_demo
from ..observability import TraceSink, build_trace_sink
from .demo import (
    VERDICT_LABEL_ZH,
    _interrupt_value,
    assemble_investigation_run,
    assemble_reference_run,
    localize_verdict,
    run_demo_profile,
)
from .settings import AppSettings, PROJECT_ROOT


class ReferenceProfileExecution:
    """Execute reference-dataset runs through the middleware runtime."""

    def __init__(
        self,
        settings: AppSettings,
        *,
        project_root: Path = PROJECT_ROOT,
        trace_sink: TraceSink | None = None,
    ):
        self.settings = settings
        self.project_root = project_root
        self.trace_sink = trace_sink

    def execute(
        self, request: RunExecutionRequest, *, emit: Any
    ) -> RunExecutionOutcome:
        trace_handler = None
        if self.trace_sink is not None:
            try:
                trace_handler = self.trace_sink.handler_for(
                    tenant_id=request.tenant_id,
                    case_id=request.case_id,
                    run_id=request.run_id,
                    session_key=f"{request.tenant_id}/{request.case_id}/{request.run_id}",
                    tags=["workbench", request.dataset_id or "alert", request.profile_id],
                )
            except Exception:
                # Observation degrades; the investigation never blocks.
                emit("graph", "可观测性适配器异常，本次运行降级为无追踪", {
                    "node": "intake",
                    "observability_degraded": True,
                })
                trace_handler = None

        store = SQLiteReferenceDataStore(self.settings.demo.data_store_path)
        try:
            result = run_demo_profile(
                store,
                dataset_id=request.dataset_id,
                case_id=request.case_id,
                profile_id=request.profile_id,
                settings=self.settings,
                emit=emit,
                run_id=request.run_id,
                trace_handler=trace_handler,
            )
        finally:
            store.close()

        artifacts: dict[str, dict[str, Any]] = {
            "demo_result": result.model_dump(mode="json")
        }
        report_id = None
        if result.investigation_report is not None:
            artifacts["investigation_report"] = result.investigation_report.model_dump(
                mode="json"
            )
            report_id = result.investigation_report.report_id
        response_plan_id = None
        plan = result.case.response_plan
        if plan is not None:
            artifacts["response_plan"] = plan.model_dump(mode="json")
        level = (
            result.case.judgment.verdict.level.value
            if result.case.judgment is not None
            else "unknown"
        )
        return RunExecutionOutcome(
            artifacts=artifacts,
            report_id=report_id,
            response_plan_id=response_plan_id,
            result_summary=f"案件处理完成：{VERDICT_LABEL_ZH.get(level, level)}",
        )


class AlertExecution:
    """Execute real-alert runs: intake channel is engine-ready; the data plane
    points at the configured activity store until Feature 01 telemetry lands."""

    def __init__(
        self,
        settings: AppSettings,
        *,
        project_root: Path = PROJECT_ROOT,
        trace_sink: TraceSink | None = None,
    ):
        self.settings = settings
        self.project_root = project_root
        self.trace_sink = trace_sink

    def _trace_handler(self, request: RunExecutionRequest, emit):
        if self.trace_sink is None:
            return None
        try:
            return self.trace_sink.handler_for(
                tenant_id=request.tenant_id,
                case_id=request.case_id,
                run_id=request.run_id,
                session_key=f"{request.tenant_id}/{request.case_id}/{request.run_id}",
                tags=["workbench", "alert"],
            )
        except Exception:
            emit("graph", "可观测性适配器异常，本次运行降级为无追踪", {
                "node": "intake", "observability_degraded": True,
            })
            return None

    def execute(self, request: RunExecutionRequest, *, emit: Any) -> RunExecutionOutcome:
        state = initialize_state(
            request.alert,
            lookback_hours=self.settings.application.investigation_lookback_hours,
        )
        state.raw_input["run_id"] = request.run_id
        activity_store = SQLiteActivityStore(
            self.settings.workbench.alert_activity_store_path, check_same_thread=False
        )
        try:
            assembly = assemble_investigation_run(
                activity_store,
                state=state,
                settings=self.settings,
                emit=emit,
                run_id=request.run_id,
                trace_handler=self._trace_handler(request, emit),
            )
            emit("graph", "AI 已开始调查：正在建立案件上下文", {
                "node": "intake", "orchestration": "framework_middleware",
            })
            result = assembly.graph.start(
                state, tenant_id=assembly.tenant_id, run_id=request.run_id
            )
            interrupt = _interrupt_value(result)
            if interrupt and interrupt.get("kind") == "response_approval":
                emit("approval", "处置方案已生成，等待人工审批", {
                    "node": "approve", "pending": True,
                    "plan": interrupt.get("response_plan") or {},
                    "request_ref": request.run_id,
                })
                artifacts: dict[str, dict[str, Any]] = {
                    "alert_payload": request.alert,
                    "response_plan": interrupt.get("response_plan") or {},
                }
                report = result.get("investigation_report")
                report_id = None
                if report is not None:
                    artifacts["investigation_report"] = report.model_dump(mode="json")
                    report_id = report.report_id
                return RunExecutionOutcome(
                    artifacts=artifacts, report_id=report_id, pending_approval=True,
                    result_summary="处置方案等待人工审批",
                )
            return self._outcome_from_result(result, request)
        finally:
            activity_store.close()

    @staticmethod
    def _outcome_from_result(result: dict, request: RunExecutionRequest) -> RunExecutionOutcome:
        artifacts: dict[str, dict[str, Any]] = {"alert_payload": request.alert}
        report_id = None
        report = result.get("investigation_report")
        if report is not None:
            artifacts["investigation_report"] = report.model_dump(mode="json")
            report_id = report.report_id
        plan = result.get("response_plan")
        if plan is not None:
            artifacts["response_plan"] = plan.model_dump(mode="json")
        return RunExecutionOutcome(
            artifacts=artifacts, report_id=report_id,
            result_summary="案件处理完成（真实告警）",
        )


def reference_case_resolver(settings: AppSettings, *, project_root: Path = PROJECT_ROOT):
    """Return the (dataset_id, profile_id) -> case_id resolver used by the
    run service; seeding the versioned reference store stays here."""

    def resolve(dataset_id: str, profile_id: str) -> str:
        store = SQLiteReferenceDataStore(settings.demo.data_store_path)
        try:
            metadata = initialize_reference_demo(
                store,
                project_root=project_root,
                tenant_id=settings.application.default_tenant,
            )
            if dataset_id not in metadata:
                raise KeyError(f"Unknown reference dataset: {dataset_id}")
            profiles = store.list_profiles(dataset_id, settings.demo.dataset_version)
            if profile_id not in {item.profile_id for item in profiles}:
                raise KeyError(f"Unknown data profile: {profile_id}")
            row = store.connection.execute(
                "SELECT case_id FROM cases WHERE dataset_id=? AND dataset_version=?",
                (dataset_id, settings.demo.dataset_version),
            ).fetchone()
            if row is None:
                raise KeyError(f"Reference dataset has no case: {dataset_id}")
            return str(row["case_id"])
        finally:
            store.close()

    return resolve


def run_service_config(settings: AppSettings) -> RunServiceConfig:
    def provider(base_url: str) -> str:
        return urlparse(base_url).hostname or "openai-compatible"

    return RunServiceConfig(
        tenant_id=settings.application.default_tenant,
        judgment_provider=provider(settings.judgment_model.base_url),
        judgment_model=settings.judgment_model.model_name or "not-configured",
        response_provider=provider(settings.response_model.base_url),
        response_model=settings.response_model.model_name or "not-configured",
    )


def build_run_service(
    settings: AppSettings,
    *,
    project_root: Path = PROJECT_ROOT,
    runtime_store=None,
) -> RunService:
    sink = build_trace_sink(settings.observability.backend)
    execution = WorkbenchExecution(
        reference=ReferenceProfileExecution(
            settings, project_root=project_root, trace_sink=sink
        ),
        alert=AlertExecution(settings, project_root=project_root, trace_sink=sink),
    )
    return RunService(
        run_service_config(settings),
        execution=execution,
        resolve_case=reference_case_resolver(settings, project_root=project_root),
        runtime_store=runtime_store,
        store_path=settings.demo.runtime_store_path,
    )


class WorkbenchExecution:
    """Dispatch execution by run source (reference preset vs real alert)."""

    def __init__(self, *, reference, alert):
        self.reference = reference
        self.alert = alert

    def execute(self, request: RunExecutionRequest, *, emit: Any) -> RunExecutionOutcome:
        impl = self.alert if request.source == "alert_json" else self.reference
        return impl.execute(request, emit=emit)


class ReferenceCheckpointAccess(CheckpointPort):
    """Rebuild the settings-derived graph for a finished run and serve its
    checkpoint history. Reconstruction is deterministic from settings plus the
    reference store, so debug access survives process restarts."""

    def __init__(self, settings: AppSettings, *, project_root: Path = PROJECT_ROOT):
        self.settings = settings
        self.project_root = project_root

    def _assemble(self, request: RunExecutionRequest, emit):
        store = SQLiteReferenceDataStore(self.settings.demo.data_store_path)
        try:
            return assemble_reference_run(
                store,
                dataset_id=request.dataset_id,
                case_id=request.case_id,
                profile_id=request.profile_id,
                settings=self.settings,
                emit=emit,
                run_id=request.run_id,
            )
        finally:
            store.close()

    @staticmethod
    def _to_ref(snapshot) -> CheckpointRef:
        metadata = snapshot.metadata or {}
        parents = metadata.get("parents") or {}
        parent_id = None
        if isinstance(parents, dict) and parents:
            parent_id = next(iter(parents.values()), None)
        return CheckpointRef(
            checkpoint_id=str(snapshot.config["configurable"].get("checkpoint_id")),
            parent_checkpoint_id=str(parent_id) if parent_id else None,
            step=int(metadata.get("step") or 0),
            node="→".join(snapshot.next) if snapshot.next else None,
            created_at=snapshot.created_at,
            metadata={"source": str(metadata.get("source") or "")},
        )

    def list_checkpoints(self, request: RunExecutionRequest) -> list[CheckpointRef]:
        assembly = self._assemble(request, emit=None)
        try:
            return [
                self._to_ref(snapshot)
                for snapshot in assembly.graph.state_history(
                    tenant_id=request.tenant_id,
                    case_id=request.case_id,
                    run_id=request.run_id,
                )
            ]
        finally:
            assembly.close()

    def state_summary(
        self, request: RunExecutionRequest, checkpoint_id: str
    ) -> DebugStateSummary:
        assembly = self._assemble(request, emit=None)
        try:
            for snapshot in assembly.graph.state_history(
                tenant_id=request.tenant_id,
                case_id=request.case_id,
                run_id=request.run_id,
            ):
                if str(snapshot.config["configurable"].get("checkpoint_id")) != checkpoint_id:
                    continue
                values = snapshot.values or {}
                investigation = values.get("investigation") or {}
                summaries: dict[str, Any] = {
                    "state_keys": sorted(str(key) for key in values.keys()),
                    "lifecycle_status": values.get("lifecycle_status"),
                    "route": values.get("route"),
                    "approval_status": values.get("approval_status"),
                    "has_report": values.get("investigation_report") is not None,
                    "has_response_plan": values.get("response_plan") is not None,
                    "next_nodes": [str(node) for node in snapshot.next],
                }
                verdict = investigation.get("verdict") if isinstance(investigation, dict) else None
                if isinstance(verdict, dict):
                    summaries["verdict"] = verdict.get("level")
                return DebugStateSummary(
                    checkpoint=self._to_ref(snapshot), node_summaries=summaries
                )
            raise KeyError(f"Unknown checkpoint: {checkpoint_id}")
        finally:
            assembly.close()

    def resume(
        self,
        request: RunExecutionRequest,
        checkpoint_id: str,
        *,
        value: dict[str, Any] | None,
        emit: Any = None,
    ) -> dict[str, Any]:
        assembly = self._assemble(request, emit=emit)
        try:
            return assembly.graph.resume_from(
                tenant_id=request.tenant_id,
                case_id=request.case_id,
                run_id=request.run_id,
                checkpoint_id=checkpoint_id,
                value=value,
            )
        finally:
            assembly.close()

    def resume_approval(self, request, *, approved, approved_by, comment=None,
                        edited_plan=None, emit=None) -> dict[str, Any]:
        assembly = self._assemble(request, emit=emit)
        try:
            return assembly.graph.resume_response(
                tenant_id=request.tenant_id,
                case_id=request.case_id,
                run_id=request.run_id,
                approved=approved,
                approved_by=approved_by,
                comment=comment,
                edited_plan=edited_plan,
            )
        finally:
            assembly.close()


class AlertCheckpointAccess:
    """Rebuild an alert run's graph; the alert payload is persisted as the
    run's alert_payload artifact so rebuilds survive restarts."""

    def __init__(self, settings: AppSettings, *, project_root: Path = PROJECT_ROOT):
        self.settings = settings
        self.project_root = project_root

    def _request_alert(self, request: RunExecutionRequest) -> dict[str, Any]:
        from ..case_management import SQLiteInvestigationRuntimeStore

        store = SQLiteInvestigationRuntimeStore(self.settings.demo.runtime_store_path)
        try:
            payload = store.get_artifact(request.tenant_id, request.run_id, "alert_payload")
        finally:
            store.close()
        if not payload:
            raise KeyError(f"Alert payload artifact missing for run {request.run_id}")
        return payload

    def _assemble(self, request: RunExecutionRequest, emit):
        raw = self._request_alert(request)
        state = initialize_state(
            raw, lookback_hours=self.settings.application.investigation_lookback_hours
        )
        state.raw_input["run_id"] = request.run_id
        activity_store = SQLiteActivityStore(
            self.settings.workbench.alert_activity_store_path, check_same_thread=False
        )
        try:
            return assemble_investigation_run(
                activity_store,
                state=state,
                settings=self.settings,
                emit=emit,
                run_id=request.run_id,
            )
        finally:
            activity_store.close()

    def list_checkpoints(self, request: RunExecutionRequest) -> list[CheckpointRef]:
        assembly = self._assemble(request, emit=None)
        try:
            return [
                ReferenceCheckpointAccess._to_ref(snapshot)
                for snapshot in assembly.graph.state_history(
                    tenant_id=request.tenant_id,
                    case_id=request.case_id,
                    run_id=request.run_id,
                )
            ]
        finally:
            assembly.close()

    def state_summary(self, request, checkpoint_id: str) -> DebugStateSummary:
        raise KeyError("Alert-run state summaries land with the M2 debug UI")

    def resume(self, request, checkpoint_id: str, *, value, emit=None):
        assembly = self._assemble(request, emit=emit)
        try:
            return assembly.graph.resume_from(
                tenant_id=request.tenant_id,
                case_id=request.case_id,
                run_id=request.run_id,
                checkpoint_id=checkpoint_id,
                value=value,
            )
        finally:
            assembly.close()

    def resume_approval(self, request, *, approved, approved_by, comment=None,
                        edited_plan=None, emit=None) -> dict[str, Any]:
        assembly = self._assemble(request, emit=emit)
        try:
            return assembly.graph.resume_response(
                tenant_id=request.tenant_id,
                case_id=request.case_id,
                run_id=request.run_id,
                approved=approved,
                approved_by=approved_by,
                comment=comment,
                edited_plan=edited_plan,
            )
        finally:
            assembly.close()


class WorkbenchCheckpointAccess(CheckpointPort):
    """Dispatch checkpoint/debug access by run source."""

    def __init__(self, settings: AppSettings, *, project_root: Path = PROJECT_ROOT):
        self.reference = ReferenceCheckpointAccess(settings, project_root=project_root)
        self.alert = AlertCheckpointAccess(settings, project_root=project_root)

    def _impl(self, request: RunExecutionRequest) -> CheckpointPort:
        return self.alert if request.source == "alert_json" else self.reference

    def list_checkpoints(self, request):
        return self._impl(request).list_checkpoints(request)

    def state_summary(self, request, checkpoint_id):
        return self._impl(request).state_summary(request, checkpoint_id)

    def resume(self, request, checkpoint_id, *, value, emit=None):
        return self._impl(request).resume(request, checkpoint_id, value=value, emit=emit)

    def resume_approval(self, request, *, approved, approved_by, comment=None,
                        edited_plan=None, emit=None):
        return self._impl(request).resume_approval(
            request, approved=approved, approved_by=approved_by,
            comment=comment, edited_plan=edited_plan, emit=emit,
        )


def build_debug_service(settings: AppSettings, run_service: RunService):
    """Debug service over the same runtime store; replay events land in the
    run's ledger marked ``debug_replay``."""

    from ..case_management import DebugService

    return DebugService(
        tenant_id=settings.application.default_tenant,
        checkpoints=ReferenceCheckpointAccess(settings, project_root=PROJECT_ROOT),
        runtime_store=run_service.runtime_store,
        emit=run_service._emit,
    )


def build_approval_service(settings: AppSettings, run_service: RunService) -> ApprovalService:
    return ApprovalService(
        tenant_id=settings.application.default_tenant,
        approvals=WorkbenchCheckpointAccess(settings, project_root=PROJECT_ROOT),
        runtime_store=run_service.runtime_store,
        run_service=run_service,
    )


def build_knowledge_overview(settings: AppSettings) -> dict[str, Any]:
    """Operator-facing knowledge surface: adapter config plus supplier catalog.

    The intranet RAG replaces the reference adapter behind the same port
    (SupplierRetrievalPort) — this overview and every page reading it stay
    unchanged."""

    from .demo import build_knowledge_service

    service = build_knowledge_service(settings)
    catalog = None
    try:
        catalog = service.catalog()
    except Exception:
        catalog = None
    knowledge = settings.knowledge
    return {
        "adapter": knowledge.adapter,
        "profile": knowledge.reference_profile if knowledge.adapter == "reference" else None,
        "timeout_seconds": knowledge.timeout_seconds,
        "catalog": catalog,
    }


class WorkbenchEventService:
    """Input surface: seed events (reference presets + submitted alerts) and
    read-only browsing over the configured activity stores."""

    def __init__(self, settings: AppSettings, *, project_root: Path = PROJECT_ROOT):
        self.settings = settings
        self.project_root = project_root
        self.tenant_id = settings.application.default_tenant

    def _reference_store(self):
        store = SQLiteReferenceDataStore(self.settings.demo.data_store_path)
        initialize_reference_demo(
            store, project_root=self.project_root, tenant_id=self.tenant_id
        )
        return store

    def _runtime_store(self):
        from ..case_management import SQLiteInvestigationRuntimeStore

        return SQLiteInvestigationRuntimeStore(self.settings.demo.runtime_store_path)

    def _alert_activity_path(self):
        return self.settings.workbench.alert_activity_store_path

    @staticmethod
    def _activity_overview(connection, tenant_id: str) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT activity_type, COUNT(*) count, MIN(observed_at) first, "
            "MAX(observed_at) last FROM normalized_activities "
            "WHERE tenant_id=? GROUP BY activity_type",
            (tenant_id,),
        ).fetchall()
        return [
            {
                "activity_type": str(row["activity_type"]),
                "count": int(row["count"]),
                "first": row["first"],
                "last": row["last"],
            }
            for row in rows
        ]

    def list_events(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        store = self._reference_store()
        try:
            rows = store.connection.execute(
                "SELECT dataset_id, dataset_version, case_id FROM cases"
            ).fetchall()
            for row in rows:
                raw = store.get_case_input(
                    str(row["dataset_id"]), str(row["dataset_version"]), str(row["case_id"])
                )
                events.append({
                    "event_id": f"ref:{row['dataset_id']}",
                    "source": "内置事件源 · 核心网演练",
                    "source_label": "核心网演练样本",
                    "host": str(raw.get("Sub_asset") or raw.get("source") or "—"),
                    "file_path": str(raw.get("File_path") or raw.get("filePath") or "—"),
                    "data_sources": len(self.data_sources(f"ref:{row['dataset_id']}")),
                    "case_id": str(row["case_id"]),
                })
        finally:
            store.close()
        latest_by_case: dict[str, str] = {}
        alert_events: list[dict[str, Any]] = []
        runtime = self._runtime_store()
        try:
            for run, dataset_id, _profile in runtime.list_runs(self.tenant_id):
                latest_by_case.setdefault(run.case_id, run.status)
                if dataset_id:
                    continue
                payload = runtime.get_artifact(self.tenant_id, run.run_id, "alert_payload")
                if not payload:
                    continue
                alert_events.append({
                    "event_id": f"alert:{run.run_id}",
                    "source": "手工提交告警",
                    "source_label": "手工提交",
                    "host": str(payload.get("Sub_asset") or payload.get("source") or "—"),
                    "file_path": str(payload.get("File_path") or payload.get("filePath") or "—"),
                    "data_sources": None,
                    "case_id": run.case_id,
                    "latest_status": run.status,
                })
        finally:
            runtime.close()
        for event in events:
            case_id = event.get("case_id") or ""
            event["latest_status"] = latest_by_case.get(case_id, "")
            event["verdict"] = None
            runtime = self._runtime_store()
            try:
                for run, dataset_id, _profile in runtime.list_runs(self.tenant_id):
                    if run.case_id != case_id:
                        continue
                    payload = runtime.get_artifact(
                        self.tenant_id, run.run_id, "investigation_report"
                    )
                    if payload and payload.get("verdict"):
                        event["verdict"] = payload["verdict"].get("level")
                        break
            finally:
                runtime.close()
        for event in alert_events:
            event["verdict"] = None
            runtime = self._runtime_store()
            try:
                payload = runtime.get_artifact(
                    self.tenant_id, event["event_id"][6:], "investigation_report"
                )
                if payload and payload.get("verdict"):
                    event["verdict"] = payload["verdict"].get("level")
            finally:
                runtime.close()
        events.extend(alert_events)
        return events

    def event_detail(self, event_id: str) -> dict[str, Any]:
        if event_id.startswith("ref:"):
            dataset_id = event_id[4:]
            store = self._reference_store()
            try:
                row = store.connection.execute(
                    "SELECT dataset_version, case_id FROM cases WHERE dataset_id=?",
                    (dataset_id,),
                ).fetchone()
                if row is None:
                    raise KeyError(f"Unknown event: {event_id}")
                raw = store.get_case_input(
                    dataset_id, str(row["dataset_version"]), str(row["case_id"])
                )
                profiles = store.list_profiles(dataset_id, str(row["dataset_version"]))
                from ..presentation.api import pages as _pages

                best = next(
                    (p for p in profiles if p.profile_id.startswith("l3")), profiles[-1]
                )
                options = "".join(
                    "<option value='" + profile.profile_id + "'"
                    + (" selected" if profile.profile_id == best.profile_id else "")
                    + ">" + _pages.profile_zh(profile.profile_id)
                    + ("　· 推荐" if profile.profile_id == best.profile_id else "")
                    + "</option>"
                    for profile in reversed(profiles)
                )
            finally:
                store.close()
            js_body = (
                "fetch('/api/investigations',{method:'POST',"
                "headers:{'content-type':'application/json'},"
                "body:JSON.stringify({reference_dataset_id:'" + dataset_id + "',"
                "profile_id:document.getElementById('pf').value})})"
                ".then(r=>r.json()).then(b=>{location.href='/workbench/runs/'+b.run_id})"
            )
            q = chr(34)
            launch_html = (
                "<label>调查档位</label><select id='pf'>" + options + "</select>"
                + "<div style='margin-top:10px'><button class='btn' onclick=" + q
                + js_body.replace(q, "&quot;") + q + ">发起排查</button></div>"
            )
            runtime = self._runtime_store()
            runs_rows = []
            try:
                for run, ds, pf in runtime.list_runs(self.tenant_id):
                    if ds == dataset_id:
                        from ..presentation.api import pages as _pages

                        runs_rows.append(
                            "<tr><td><a class='id-short' href='/workbench/runs/" + run.run_id
                            + "' title='" + run.run_id + "'>" + run.run_id[:10] + "…</a></td><td>"
                            + _pages.STATUS_ZH.get(run.status, run.status)
                            + "</td><td class='muted'>" + _pages.profile_zh(pf) + "</td></tr>"
                        )
            finally:
                runtime.close()
            runs_html = (
                "<table><thead><tr><th>调查任务</th><th>状态</th><th>证据范围</th></tr></thead><tbody>"
                + ("".join(runs_rows) or "<tr><td colspan='3' class='muted'>尚未排查</td></tr>")
                + "</tbody></table>"
            )
            from .demo import CASE_STORIES

            story = CASE_STORIES.get(dataset_id) or {}
            return {
                "event_id": event_id,
                "source": "内置事件源 · 核心网演练",
                "title": story.get("title"),
                "badge": story.get("badge"),
                "lead": story.get("lead"),
                "payload": raw,
                "case_id": str(row["case_id"]),
                "launch_html": launch_html,
                "runs_html": runs_html,
            }
        if event_id.startswith("alert:"):
            run_id = event_id[6:]
            runtime = self._runtime_store()
            try:
                payload = runtime.get_artifact(self.tenant_id, run_id, "alert_payload")
                run = runtime.get_run(self.tenant_id, run_id)
            finally:
                runtime.close()
            if not payload or run is None:
                raise KeyError(f"Unknown event: {event_id}")
            return {
                "event_id": event_id,
                "source": "手工提交告警",
                "payload": payload,
                "case_id": run.case_id,
                "launch_html": (
                    "<p class='muted'>该告警已建案并调查：<a class='mono' href='/workbench/runs/"
                    + run_id + "'>" + run_id + "</a>（" + run.status + "）</p>"
                ),
                "runs_html": "",
            }
        raise KeyError(f"Unknown event: {event_id}")

    def data_sources(self, event_id: str | None = None) -> list[dict[str, Any]]:
        from ..data_foundation.adapters import SQLiteActivityStore
        from ..data_foundation.application import reference_activity_store_path

        merged: dict[str, dict[str, Any]] = {}
        if event_id and event_id.startswith("ref:"):
            store = self._reference_store()
            try:
                paths = [reference_activity_store_path(store.path, event_id[4:])]
            finally:
                store.close()
        elif event_id and event_id.startswith("alert:"):
            paths = [self._alert_activity_path()]
        else:
            paths = [self._alert_activity_path()]
            ref_store = self._reference_store()
            try:
                for row in ref_store.connection.execute(
                    "SELECT DISTINCT dataset_id FROM cases"
                ).fetchall():
                    paths.append(
                        reference_activity_store_path(ref_store.path, str(row["dataset_id"]))
                    )
            finally:
                ref_store.close()
        for path in paths:
            if not Path(path).exists():
                continue
            store = SQLiteActivityStore(path, check_same_thread=False)
            try:
                for item in self._activity_overview(store.connection, self.tenant_id):
                    existing = merged.setdefault(item["activity_type"], dict(item))
                    if existing is not item:
                        existing["count"] += item["count"]
                        existing["first"] = min(existing["first"] or "9999", item["first"] or "9999")
                        existing["last"] = max(existing["last"] or "", item["last"] or "")
            finally:
                store.close()
        return sorted(merged.values(), key=lambda item: -item["count"])

    def data_samples(self, activity_type: str, limit: int = 20) -> list[dict[str, Any]]:
        import json as json_lib

        from ..data_foundation.adapters import SQLiteActivityStore
        from ..data_foundation.application import reference_activity_store_path

        records: list[dict[str, Any]] = []
        paths = [self._alert_activity_path()]
        ref_store = self._reference_store()
        try:
            for row in ref_store.connection.execute(
                "SELECT DISTINCT dataset_id FROM cases"
            ).fetchall():
                paths.append(
                    reference_activity_store_path(ref_store.path, str(row["dataset_id"]))
                )
        finally:
            ref_store.close()
        for path in paths:
            if not Path(path).exists() or len(records) >= limit:
                continue
            store = SQLiteActivityStore(path, check_same_thread=False)
            try:
                rows = store.connection.execute(
                    "SELECT payload_json FROM normalized_activities "
                    "WHERE tenant_id=? AND activity_type=? ORDER BY observed_at DESC LIMIT ?",
                    (self.tenant_id, activity_type, limit - len(records)),
                ).fetchall()
                for row in rows:
                    try:
                        records.append(json_lib.loads(row["payload_json"]))
                    except ValueError:
                        continue
            finally:
                store.close()
        return records


def build_event_service(settings: AppSettings, *, project_root: Path = PROJECT_ROOT):
    return WorkbenchEventService(settings, project_root=project_root)


def build_settings_overview(settings: AppSettings) -> dict[str, Any]:
    def host(base_url: str) -> str:
        from urllib.parse import urlparse

        return urlparse(base_url).hostname or base_url

    items = [
        ("研判模型", settings.judgment_model.model_name or "—"),
        ("处置模型", settings.response_model.model_name or "—"),
        ("报告模型", settings.report_model.model_name or "—"),
        ("模型服务", "已配置" if settings.judgment_model.model_name else "未配置"),
        ("调查轮次预算", str(settings.judgment_budget.max_iterations)),
        ("工具调用预算", str(settings.judgment_budget.max_tool_calls)),
        ("进度保存", {"sqlite": "本地持久化", "memory": "仅进程内"}.get(
            settings.checkpoint.backend, settings.checkpoint.backend)),
        ("运行追踪", {"none": "未启用", "langfuse": "已启用"}.get(
            settings.observability.backend, settings.observability.backend)),
    ]
    return {"items": items, "knowledge_adapter": settings.knowledge.adapter}
