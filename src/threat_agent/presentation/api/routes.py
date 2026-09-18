"""Workbench HTTP surface: APIs + pages. Thin layer over injected services.

Architecture rules (test_architecture_dependencies): this package consumes
stable contracts and its own Port protocols only — every capability is
composed in bootstrap and injected here.
"""

from __future__ import annotations

import csv
import html
import io
import json
import time
from typing import Any, Protocol

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse

from ...contracts import (
    ApprovalDecision,
    InvestigationCreateRequest,
    InvestigationRunReadModel,
)
from ..projection.case_projector import case_read_payload
from ..read_model.store import CaseReadStore
from ..read_model.demo_store import DemoComparisonStore
from . import pages


class DemoRunServicePort(Protocol):
    def start(self, dataset_id: str, profile_id: str) -> str: ...
    def get_investigation(self, run_id: str) -> InvestigationRunReadModel | None: ...
    def list_runs(self) -> list: ...
    def get_trajectory(self, run_id: str): ...
    def start_alert(self, raw_alert: dict) -> str: ...
    def get_evidence(self, run_id: str, ref: str) -> list: ...
    def list_audit(self, *, action=None, run_id=None, limit=300) -> list: ...
    def case_index(self) -> list: ...
    def knowledge_stats(self) -> dict: ...


class ApprovalServicePort(Protocol):
    def list_pending(self) -> list: ...
    def decide(self, run_id: str, decision) -> dict: ...


class DebugServicePort(Protocol):
    def list_checkpoints(self, run_id: str) -> list: ...
    def state_summary(self, run_id: str, checkpoint_id: str): ...
    def resume(self, run_id: str, checkpoint_id: str, *, value=None) -> dict: ...


class EventServicePort(Protocol):
    def list_events(self) -> list: ...
    def event_detail(self, event_id: str) -> dict: ...
    def data_sources(self, event_id: str | None = None) -> list: ...
    def data_samples(self, activity_type: str, limit: int = 20) -> list: ...


def _fmt_dur(value):
    if value is None:
        return "—"
    return f"{value:.0f}ms" if value < 1000 else f"{value / 1000:.1f}s"


def _fmt_token(u):
    """Compact token figure for event rows (never raw JSON)."""

    if not u:
        return "—"
    inpt = u.get("input_tokens") or u.get("prompt_tokens") or 0
    out = u.get("output_tokens") or u.get("completion_tokens") or 0

    def k(n: int) -> str:
        return f"{n / 1000:.1f}k" if n >= 1000 else str(n)

    return f"↑{k(inpt)} ↓{k(out)}"


def fmt_token_pair(u: dict) -> str:
    """Compact human token figure: 192.4k / 18.6k."""

    if not u:
        return "—"
    inpt = u.get("input_tokens") or u.get("prompt_tokens") or 0
    out = u.get("output_tokens") or u.get("completion_tokens") or 0

    def k(n: int) -> str:
        return f"{n / 1000:.1f}k" if n >= 1000 else str(n)

    return f"{k(inpt)} / {k(out)}"


def create_app(
    store: CaseReadStore,
    demo_store: DemoComparisonStore | None = None,
    demo_run_service: DemoRunServicePort | None = None,
    approval_service: ApprovalServicePort | None = None,
    debug_service: DebugServicePort | None = None,
    knowledge_overview: dict | None = None,
    event_service: EventServicePort | None = None,
    settings_overview: dict | None = None,
) -> FastAPI:
    app = FastAPI(title="Unknown File Threat Agent", version="2.0")

    def load(case_id: str, tenant_id: str):
        item = store.get(tenant_id, case_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return item

    def _run_or_404(run_id: str) -> InvestigationRunReadModel:
        if demo_run_service is None:
            raise HTTPException(status_code=503, detail="Investigation runner is not configured")
        item = demo_run_service.get_investigation(run_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Investigation run not found")
        return item

    # ------------------------------------------------------------- health

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # ------------------------------------------------------------- cases

    @app.get("/api/cases/{case_id}")
    def get_case(case_id: str, x_tenant_id: str = Header(default="default")) -> dict:
        return case_read_payload(load(case_id, x_tenant_id))

    @app.get("/cases/{case_id}")
    def case_page(case_id: str, x_tenant_id: str = Header(default="default")):
        return RedirectResponse("/workbench/cases")

    # ------------------------------------------------------------- demo data

    @app.get("/api/datasets")
    def list_datasets() -> dict[str, Any]:
        items = []
        for dataset_id in (demo_store.dataset_ids() if demo_store is not None else []):
            item = demo_store.get(dataset_id)
            items.append({
                "dataset_id": dataset_id,
                "profiles": [
                    {"profile_id": profile.profile_id, "level": profile.level}
                    for profile in (item.profiles if item else [])
                ],
            })
        return {"datasets": items}

    # ------------------------------------------------------------- runs

    @app.post("/api/investigations", status_code=202)
    def start_investigation(payload: InvestigationCreateRequest) -> dict[str, str]:
        if demo_run_service is None:
            raise HTTPException(status_code=503, detail="Investigation runner is not configured")
        try:
            run_id = demo_run_service.start(payload.reference_dataset_id, payload.profile_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        return {"run_id": run_id, "status": "queued", "location": f"/api/runs/{run_id}"}

    @app.get("/api/investigations/{run_id}")
    def get_investigation_alias(run_id: str) -> dict[str, Any]:
        return _run_or_404(run_id).model_dump(mode="json")

    @app.get("/api/runs")
    def list_runs() -> dict[str, Any]:
        if demo_run_service is None:
            raise HTTPException(status_code=503, detail="Investigation runner is not configured")
        summaries = []
        for item in demo_run_service.list_runs():
            payload = item.model_dump(mode="json")
            detail = demo_run_service.get_investigation(item.run.run_id)
            token: dict[str, int] = {}
            for event in detail.events:
                for key, value in (event.token_usage or {}).items():
                    token[key] = token.get(key, 0) + int(value)
            payload["token_usage"] = token
            # Display labels: templates consume these instead of raw enum values.
            payload["source_label"] = pages.dataset_zh(item.dataset_id)
            payload["profile_label"] = pages.profile_zh(item.profile_id)
            payload["status_label"] = pages.STATUS_ZH.get(item.run.status, item.run.status)
            payload["stage_label"] = pages.stage_zh(item.run.stage)
            summaries.append(payload)
        return {"runs": summaries}

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
        return _run_or_404(run_id).model_dump(mode="json")

    @app.post("/api/runs/{run_id}/replay", status_code=202)
    def replay_run(run_id: str) -> dict[str, str]:
        if demo_run_service is None:
            raise HTTPException(status_code=503, detail="Investigation runner is not configured")
        try:
            new_run_id = demo_run_service.replay(run_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        return {"run_id": new_run_id, "status": "queued"}

    @app.get("/api/runs/{run_id}/evidence/{ref}")
    def run_evidence(run_id: str, ref: str) -> dict[str, Any]:
        _run_or_404(run_id)
        events = demo_run_service.get_evidence(run_id, ref)
        return {"ref": ref, "events": [e.model_dump(mode="json") for e in events]}

    @app.get("/api/runs/{run_id}/events/stream")
    def run_event_stream(run_id: str, until: int | None = None) -> StreamingResponse:
        _run_or_404(run_id)

        def generate():
            last = 0
            idle = 0
            while True:
                current = demo_run_service.get_investigation(run_id)
                if current is None:
                    return
                fresh = [e for e in current.events if e.sequence > last]
                for event in fresh:
                    last = event.sequence
                    payload = json.dumps(event.model_dump(mode="json"), ensure_ascii=False)
                    yield "data: " + payload + chr(10) + chr(10)
                if until is not None and last >= until:
                    return
                if not fresh:
                    idle += 1
                    if idle > 240:
                        return
                    time.sleep(0.5)
                else:
                    idle = 0

        return StreamingResponse(
            generate(), media_type="text/event-stream",
            headers={"Cache-Control": "no-cache"},
        )

    # ------------------------------------------------------------- intake

    @app.post("/api/intake", status_code=202)
    def intake_alert(payload: dict[str, Any]) -> dict[str, str]:
        if demo_run_service is None:
            raise HTTPException(status_code=503, detail="Investigation runner is not configured")
        alert = payload.get("alert")
        if not isinstance(alert, dict) or not alert:
            raise HTTPException(status_code=422, detail="alert payload is required")
        run_id = demo_run_service.start_alert(alert)
        return {"run_id": run_id, "status": "queued", "location": f"/api/runs/{run_id}"}

    @app.post("/api/intake/batch", status_code=202)
    def intake_batch(payload: dict[str, Any]) -> dict[str, Any]:
        if demo_run_service is None:
            raise HTTPException(status_code=503, detail="Investigation runner is not configured")
        alerts = payload.get("alerts")
        if not isinstance(alerts, list) or not alerts:
            raise HTTPException(status_code=422, detail="alerts array is required")
        accepted, failed, run_ids = 0, 0, []
        for alert in alerts:
            if not isinstance(alert, dict) or not alert:
                failed += 1
                continue
            try:
                run_ids.append(demo_run_service.start_alert(alert))
                accepted += 1
            except Exception:
                failed += 1
        return {"accepted": accepted, "failed": failed, "run_ids": run_ids}

    # ------------------------------------------------------------- approvals

    @app.get("/api/approvals")
    def list_approvals() -> dict[str, Any]:
        if approval_service is None:
            raise HTTPException(status_code=503, detail="Approval service is not configured")
        approvals = []
        for item in approval_service.list_pending():
            payload = item.model_dump(mode="json")
            # One shared card renderer for both surfaces (desk + inline on the
            # live investigation page) guarantees identical decision UX.
            payload["card_html"] = pages.approval_card_html(item)
            approvals.append(payload)
        return {"approvals": approvals}

    @app.post("/api/approvals/{run_id}")
    def decide_approval(run_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        if approval_service is None:
            raise HTTPException(status_code=503, detail="Approval service is not configured")
        try:
            decision = ApprovalDecision.model_validate(payload)
            result = approval_service.decide(run_id, decision)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        return result

    # ------------------------------------------------------------- audit

    @app.get("/api/audit")
    def list_audit(
        action: str | None = None,
        run_id: str | None = None,
        action_label: str | None = None,
    ) -> dict[str, Any]:
        if demo_run_service is None:
            raise HTTPException(status_code=503, detail="Investigation runner is not configured")
        if action_label:
            events = demo_run_service.list_audit(run_id=run_id, limit=5000)
            events = [
                e for e in events
                if pages.ACTION_ZH.get(e.action, e.action) == action_label
            ][:300]
        else:
            events = demo_run_service.list_audit(action=action, run_id=run_id)
        payloads = []
        for event in events:
            payload = event.model_dump(mode="json")
            payload["action_label"] = pages.ACTION_ZH.get(event.action, event.action)
            payload["resource_label"] = pages.resource_zh(event.resource_type)
            payload["result_summary"] = pages.display_summary(event.result_summary)
            payloads.append(payload)
        # Distinct translated actions for the filter dropdown.
        actions = sorted({p["action_label"] for p in payloads})
        return {"audit": payloads, "actions": actions}

    @app.get("/api/audit/export.csv")
    def export_audit_csv() -> Response:
        if demo_run_service is None:
            raise HTTPException(status_code=503, detail="Investigation runner is not configured")
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["created_at", "action", "resource_type", "resource_ref",
                         "run_id", "case_id", "result_summary"])
        for e in demo_run_service.list_audit(limit=5000):
            # CSV is a deliverable: it goes through the same display gate as the UI.
            writer.writerow([
                e.created_at,
                pages.ACTION_ZH.get(e.action, e.action),
                pages.resource_zh(e.resource_type),
                e.resource_ref,
                e.run_id, e.case_id,
                pages.display_summary(e.result_summary),
            ])
        return Response(
            buffer.getvalue(), media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=audit.csv"},
        )

    # ------------------------------------------------------------- cases / knowledge

    @app.get("/api/cases-view")
    def cases_view() -> dict[str, Any]:
        if demo_run_service is None:
            raise HTTPException(status_code=503, detail="Investigation runner is not configured")
        cases = demo_run_service.case_index()
        for entry in cases:
            payload = demo_run_service.get_investigation(entry["latest_run_id"])
            report = payload.investigation_report if payload else None
            entry["publication_status"] = report.publication_status if report else None
        return {"cases": cases}

    @app.get("/api/settings-view")
    def settings_view() -> dict[str, Any]:
        if settings_overview is None:
            raise HTTPException(status_code=503, detail="Settings surface is not configured")
        return settings_overview

    @app.get("/api/knowledge")
    def knowledge_view() -> dict[str, Any]:
        if knowledge_overview is None or demo_run_service is None:
            raise HTTPException(status_code=503, detail="Knowledge surface is not configured")
        stats = demo_run_service.knowledge_stats()
        stats["recent"] = [
            {**item, "message": pages.translate_knowledge_message(item.get("message") or ""),
             "status_label": pages.KNOWLEDGE_STATUS_ZH.get(item.get("status") or "", item.get("status") or "")}
            for item in stats.get("recent") or []
        ]
        stats["status_labels"] = {
            pages.KNOWLEDGE_STATUS_ZH.get(k, k): v for k, v in (stats.get("by_status") or {}).items()
        }
        stats["category_labels"] = {
            pages.SOURCE_CATEGORY_ZH.get(k, k): v for k, v in (stats.get("by_category") or {}).items()
        }
        return {**knowledge_overview, "stats": stats}

    # ------------------------------------------------------------- debug

    @app.get("/api/debug/runs/{run_id}/checkpoints")
    def list_checkpoints(run_id: str) -> dict[str, Any]:
        if debug_service is None:
            raise HTTPException(status_code=503, detail="Debug service is not enabled")
        _run_or_404(run_id)
        try:
            refs = debug_service.list_checkpoints(run_id)
        except KeyError as error:
            # A run may have no rebuildable context; that is a per-run limit,
            # not a missing debug service (which would be 503).
            raise HTTPException(
                status_code=404, detail=f"该运行暂无可回溯的检查点：{error}"
            ) from error
        return {"checkpoints": [ref.model_dump(mode="json") for ref in refs]}

    @app.get("/api/debug/runs/{run_id}/checkpoints/{checkpoint_id}/state")
    def checkpoint_state(run_id: str, checkpoint_id: str) -> dict[str, Any]:
        if debug_service is None:
            raise HTTPException(status_code=503, detail="Debug service is not enabled")
        try:
            summary = debug_service.state_summary(run_id, checkpoint_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        return summary.model_dump(mode="json")

    @app.post("/api/debug/runs/{run_id}/resume", status_code=202)
    def resume_checkpoint(run_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        if debug_service is None:
            raise HTTPException(status_code=503, detail="Debug service is not enabled")
        checkpoint_id = str(payload.get("checkpoint_id") or "")
        if not checkpoint_id:
            raise HTTPException(status_code=422, detail="checkpoint_id is required")
        _run_or_404(run_id)
        # Replay can run a full LLM chain: launch in background, progress
        # streams into the run ledger as debug-marked events.
        import threading

        threading.Thread(
            target=debug_service.resume,
            args=(run_id, checkpoint_id),
            kwargs={"value": payload.get("value")},
            name=f"debug-resume-{run_id}",
            daemon=True,
        ).start()
        return {"status": "replaying", "checkpoint_id": checkpoint_id}

    # ------------------------------------------------------------- events / data

    @app.get("/api/events")
    def list_events() -> dict[str, Any]:
        if event_service is None:
            raise HTTPException(status_code=503, detail="Event service is not configured")
        return {"events": event_service.list_events()}

    @app.get("/api/events/{event_id}")
    def event_detail_route(event_id: str) -> dict[str, Any]:
        if event_service is None:
            raise HTTPException(status_code=503, detail="Event service is not configured")
        try:
            return event_service.event_detail(event_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @app.get("/api/data/sources")
    def data_sources() -> dict[str, Any]:
        if event_service is None:
            raise HTTPException(status_code=503, detail="Event service is not configured")
        return {"sources": event_service.data_sources()}

    @app.get("/api/data/sources/{activity_type}")
    def data_samples(activity_type: str) -> dict[str, Any]:
        if event_service is None:
            raise HTTPException(status_code=503, detail="Event service is not configured")
        return {"activity_type": activity_type,
                "records": event_service.data_samples(activity_type)}

    # ------------------------------------------------------------- report export

    @app.get("/api/runs/{run_id}/report.md")
    def export_report(run_id: str) -> Response:
        item = _run_or_404(run_id)
        lines = [f"# 研判报告 · {run_id}"]
        report = item.investigation_report
        if report is None:
            lines.append("\n（本次运行未发布报告）")
        else:
            hosts = ", ".join(report.asserted_host_refs) or "—"
            lines += [
                f"\n**结论**：{pages.VERDICT_ZH.get(report.verdict.level.value, report.verdict.level.value)}  ",
                f"**发布状态**：{pages.PUBLICATION_ZH.get(report.publication_status, report.publication_status)}  ",
                f"**资产**：{hosts}",
                f"\n{report.executive_summary}\n",
            ]
            if report.key_evidence:
                lines.append("\n## 关键证据\n")
                for st in report.key_evidence:
                    lines.append(f"- {st.text}（引用：{', '.join(st.supporting_refs) or '—'}）")
            if report.limitations:
                lines.append("\n## 结论边界\n")
                for text in report.limitations:
                    lines.append(f"- {pages.display_summary(text)}")
        plan = item.response_plan
        if plan is not None and plan.actions:
            lines.append("\n## 处置方案\n")
            for action in plan.actions:
                lines.append(
                    f"- **{pages.ACTION_TYPES_ZH.get(action.action_type, action.action_type)}**"
                    f"（{pages.approval_class_zh(action.approval_class)}）：{action.rationale}"
                )
        markdown = "\n".join(lines)
        return Response(
            markdown, media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename={run_id}-report.md"},
        )

    # ------------------------------------------------------------- pages

    @app.get("/workbench", response_class=HTMLResponse)
    def workbench_page() -> str:
        if demo_run_service is None:
            raise HTTPException(status_code=503, detail="Investigation runner is not configured")
        pending_count = len(approval_service.list_pending()) if approval_service is not None else None
        return pages.render_workbench(pending_count)

    @app.get("/workbench/events", response_class=HTMLResponse)
    def events_page() -> str:
        if event_service is None:
            raise HTTPException(status_code=503, detail="Event service is not configured")
        return pages.render_events()

    @app.get("/workbench/events/{event_id}", response_class=HTMLResponse)
    def event_page(event_id: str) -> str:
        if event_service is None:
            raise HTTPException(status_code=503, detail="Event service is not configured")
        try:
            detail = event_service.event_detail(event_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        sources = event_service.data_sources(event_id)
        domain_zh = {
            "process": "进程与命令", "network": "网络连接", "socket": "网络收发",
            "file": "文件变更", "service": "系统服务", "package": "软件包来源",
            "asset": "资产基线", "extension": "扩展记录",
        }
        if sources:
            sources_html = (
                "<div style='display:flex;flex-direction:column;gap:8px'>"
                + "".join(
                    "<div style='display:flex;align-items:center;gap:10px;border:1px solid var(--line);"
                    "border-radius:10px;padding:8px 12px;background:#fbfbfd'>"
                    f"<span class='pill info'>{html.escape(domain_zh.get(str(item['activity_type']), str(item['activity_type'])))}</span>"
                    f"<b>{item['count']} 条</b>"
                    f"<span class='muted mono' style='margin-left:auto;font-size:10.5px'>"
                    f"{html.escape(str(item.get('first') or '—'))[:19]} 起</span></div>"
                    for item in sources
                )
                + "</div>"
            )
        else:
            sources_html = "<p class='muted'>该事件暂无可访问的活动数据（接入后此处显示各域概览）。</p>"

        payload = detail.get("payload") or {}

        def pick(*keys, default="—"):
            for key in keys:
                if payload.get(key) not in (None, ""):
                    return str(payload[key])
            return default

        sha = pick("File_hash", "fileHash", "file_hash")
        fields = [
            ("告警标识", pick("File_id", "file_id")),
            ("主机资产", pick("Sub_asset", "sub_asset", "source")),
            ("可疑文件路径", pick("File_path", "filePath", "file_path")),
            ("SHA256", (sha[:32] + "…") if len(sha) > 32 else sha),
            ("发现时间", pick("discovery_time", "Discovery_Time")),
            ("上报来源", pick("source", "Source")),
        ]
        fields_html = (
            "<table class='field-table'><tbody>"
            + "".join(
                f"<tr><td>{html.escape(label)}</td><td class='mono' title='{html.escape(value)}'>"
                f"{html.escape(value if len(value) <= 46 else value[:46] + '…')}</td></tr>"
                for label, value in fields
            )
            + "</tbody></table>"
        )
        return pages.render_event_detail(
            event_id=event_id,
            detail=detail,
            fields_html=fields_html,
            sources_html=sources_html,
            runs_html=detail.get("runs_html") or "",
            launch_html=detail.get("launch_html") or "",
        )

    @app.get("/workbench/data", response_class=HTMLResponse)
    def data_page() -> str:
        if event_service is None:
            raise HTTPException(status_code=503, detail="Event service is not configured")
        return pages.render_data_browser(event_service.data_sources())

    @app.get("/workbench/settings", response_class=HTMLResponse)
    def settings_page() -> str:
        if settings_overview is None:
            raise HTTPException(status_code=503, detail="Settings surface is not configured")
        return pages.render_settings(settings_overview)

    @app.get("/workbench/approvals", response_class=HTMLResponse)
    def approvals_page() -> str:
        if approval_service is None:
            raise HTTPException(status_code=503, detail="Approval service is not configured")
        return pages.render_approvals(len(approval_service.list_pending()))

    @app.get("/workbench/audit", response_class=HTMLResponse)
    def audit_page() -> str:
        return pages.render_audit()

    @app.get("/workbench/cases", response_class=HTMLResponse)
    def cases_page() -> str:
        if demo_run_service is None:
            raise HTTPException(status_code=503, detail="Investigation runner is not configured")
        return pages.render_cases()

    @app.get("/workbench/knowledge", response_class=HTMLResponse)
    def knowledge_page() -> str:
        if knowledge_overview is None or demo_run_service is None:
            raise HTTPException(status_code=503, detail="Knowledge surface is not configured")
        return pages.render_knowledge(
            knowledge_overview.get("adapter") or "null",
            knowledge_overview.get("profile"),
            knowledge_overview.get("catalog"),
            # Same enriched payload the JSON endpoint serves: one translation
            # gate, so the page can never disagree with the API.
            knowledge_view()["stats"],
        )

    @app.get("/workbench/compare", response_class=HTMLResponse)
    def compare_page(a: str = "", b: str = "") -> str:
        if not a or not b:
            raise HTTPException(status_code=422, detail="a and b run ids are required")
        return pages.render_compare(a, b)

    @app.get("/workbench/runs/{run_id}", response_class=HTMLResponse)
    def run_page(run_id: str) -> str:
        if demo_run_service is None:
            raise HTTPException(status_code=503, detail="Investigation runner is not configured")
        investigation = demo_run_service.get_investigation(run_id)
        trajectory = demo_run_service.get_trajectory(run_id)
        if trajectory is None or investigation is None:
            raise HTTPException(status_code=404, detail="Investigation run not found")
        run = investigation.run
        status = run.status

        all_entries = [
            item for r in trajectory.rounds for item in r.entries
        ] + list(trajectory.phase_entries)
        durations = [item.duration_ms for item in all_entries if item.duration_ms]
        max_duration = max(durations) if durations else 0

        def entries_html(items):
            parts = []
            for item in items:
                refs = " ".join(
                    f'<a class="evref" data-ref="{html.escape(ref)}" href="#">{html.escape(ref)}</a>'
                    for ref in item.evidence_refs
                ) or "—"
                detail_text = json.dumps(item.detail, ensure_ascii=False, indent=1)
                if item.kind in ("model_input", "model_output") and len(detail_text) > 1200:
                    detail_text = detail_text[:1200] + "\n…（长内容已截断）"
                detail = html.escape(detail_text)
                debug_mark = "<span class='tag debug'>debug</span> " if item.detail.get("debug_replay") else ""
                bar = ""
                if item.duration_ms and max_duration:
                    width = max(2, int(item.duration_ms / max_duration * 100))
                    bar = (f"<div class='wf' title='{html.escape(_fmt_dur(item.duration_ms))}'>"
                           f"<i style='width:{width}%'></i></div>")
                token = " · " + html.escape(_fmt_token(item.token_usage)) if item.token_usage else ""
                dur = (f"<span class='muted mono' style='margin-left:auto'>"
                       f"{html.escape(_fmt_dur(item.duration_ms))}</span>") if item.duration_ms else ""
                parts.append(
                    f"<details class='entry'><summary><span class='tag {html.escape(item.kind)}'>"
                    f"{html.escape(pages.kind_zh(item.kind))}</span>{debug_mark} "
                    f"{html.escape(item.summary)}{dur}</summary>"
                    f"{bar}<div class='refs'>节点 {html.escape(item.node or '·')} · 证据: {refs}{token}</div>"
                    f"<pre>{detail}</pre></details>"
                )
            return "".join(parts)

        rounds_html = ""
        knowledge_items = []
        for round_item in trajectory.rounds:
            for item in round_item.entries:
                if item.kind == "knowledge":
                    knowledge_items.append(item)
            observation = round_item.observation or "（本轮无观察句）"
            # Kept out of the f-string expression: a backslash inside an
            # f-string expression is a syntax error before Python 3.12.
            entries = entries_html(round_item.entries) or "<p class='muted'>本轮无明细事件</p>"
            rounds_html += (
                f"<div class='round'><h3>第 {round_item.index} 轮</h3>"
                f"<p class='obs'>{html.escape(observation)}</p>"
                f"{entries}"
                f"</div>"
            )
        for item in trajectory.phase_entries:
            if item.kind == "knowledge":
                knowledge_items.append(item)
        phases_html = entries_html(trajectory.phase_entries)
        knowledge_html = "".join(
            pages.knowledge_card_html(item) for item in knowledge_items
        ) or "<p class='muted'>本次运行没有知识检索记录</p>"

        report = investigation.investigation_report
        if report is not None:
            verdict_key = report.verdict.level.value
            verdict_zh = pages.VERDICT_ZH.get(verdict_key, verdict_key)
            key_evidence = "".join(
                "<div class='ev-item'>" + html.escape(st.text)
                + " ".join(
                    f"<a class='evref' data-ref='{html.escape(ref)}' href='#'>"
                    f"<span class='mono'>{html.escape(ref)}</span></a>"
                    for ref in st.supporting_refs
                )
                + "</div>"
                for st in report.key_evidence
            ) or "<p class='muted'>无关键证据（兜底发布）</p>"
            fallback = (
                "<div class='fallback-warn'>⚠ 兜底发布：未通过证据接地校验，本报告不含任何安全结论断言。</div>"
                if report.publication_status == "fallback"
                else ""
            )
            plan = investigation.response_plan
            plan_html = ""
            if plan is not None:
                plan_note = (
                    "<p class='muted' style='margin:4px 0'>本方案为" + html.escape(pages.PLAN_STATUS_ZH.get(plan.status, "建议性"))
                    + "输出：产生需要人工确认的处置动作时，调查会停在此处等待审批。</p>"
                )
                plan_html = (
                    "<h4>处置方案 · "
                    + html.escape(pages.PLAN_STATUS_ZH.get(plan.status, plan.status)) + "</h4>" + plan_note
                    + "".join(
                        "<div class='action-item'><b>"
                        + html.escape(pages.ACTION_TYPES_ZH.get(a.action_type, a.action_type))
                        + "</b> <span class='pill info'>"
                        + html.escape(pages.approval_class_zh(a.approval_class))
                        + "</span><br>" + html.escape(a.rationale or "")
                        + "<br><span class='muted'>业务影响："
                        + html.escape(a.expected_impact or "待评估") + "</span></div>"
                        for a in plan.actions
                    )
                )
            hero_tone = (
                "bad" if verdict_key in ("confirmed_malicious", "likely_malicious")
                else "warn" if verdict_key == "suspicious"
                else "ok" if verdict_key in ("benign", "likely_benign")
                else ""
            )
            pub_label = pages.PUBLICATION_ZH.get(report.publication_status, report.publication_status)
            pub_tone = "ok" if report.publication_status == "grounded" else "warn"

            key_evidence = "".join(
                "<div class='ev-card'><span class='ev-idx'>" + str(index) + "</span>"
                "<div class='ev-body'><p class='ev-text'>" + html.escape(st.text) + "</p>"
                + (
                    "<div class='ev-refs'>"
                    + "".join(
                        f"<a class='evref' data-ref='{html.escape(ref)}' href='#'>{html.escape(ref)}</a>"
                        for ref in st.supporting_refs
                    )
                    + "</div>"
                    if st.supporting_refs else ""
                )
                + "</div></div>"
                for index, st in enumerate(report.key_evidence, start=1)
            ) or "<p class='muted'>本次报告不含关键证据条目。</p>"

            limit_items = "".join(
                f"<li>{html.escape(pages.display_summary(text))}</li>"
                for text in report.limitations
            )
            counter_items = "".join(
                f"<li>{html.escape(st.text)}</li>" for st in report.counter_evidence
            )

            plan = investigation.response_plan
            plan_html = ""
            if plan is not None and plan.actions:
                needs_approval = [
                    a for a in plan.actions
                    if str(a.approval_class or "") not in ("", "none", "recommended")
                ]
                plan_html = (
                    "<div class='report-sec plan-section'>"
                    "<h4><span class='bar'></span>处置方案"
                    + f" <span class='pill {'warn' if needs_approval else 'info'}'>"
                    + html.escape(pages.PLAN_STATUS_ZH.get(plan.status, plan.status)) + "</span></h4>"
                    + "<div class='plan-list'>"
                    + "".join(
                        "<div class='plan-card" + (" lead" if a in needs_approval else "") + "'>"
                        + "<div class='plan-head'><span class='plan-idx'>" + str(index) + "</span>"
                        + "<b>" + html.escape(pages.ACTION_TYPES_ZH.get(a.action_type, a.action_type)) + "</b>"
                        + "<span class='pill info'>"
                        + html.escape(pages.approval_class_zh(a.approval_class)) + "</span></div>"
                        + f"<p class='plan-why'>{html.escape(a.rationale or '')}</p>"
                        + "<div class='plan-impact'><span>预期影响</span><b>"
                        + html.escape(a.expected_impact or "待评估") + "</b></div></div>"
                        for index, a in enumerate(plan.actions, start=1)
                    )
                    + "</div>"
                    + f"<div class='plan-foot'>共 {len(plan.actions)} 项动作"
                    + (f" · 其中 {len(needs_approval)} 项需人工审批" if needs_approval else "")
                    + " · 本系统不自动执行生产处置动作</div>"
                    + "</div>"
                )

            report_html = (
                "<div class='card' style='margin-top:16px'>"
                + "<div class='verdict-hero " + hero_tone + "'>"
                + "<div><span class='vh-label'>研判结论</span>"
                + f"<span class='vh-level {verdict_key}'>{html.escape(verdict_zh)}</span></div>"
                + "<div class='vh-side'>"
                + f"<span class='pill {pub_tone}'>{html.escape(pub_label)}</span>"
                + f"<span class='hint mono'>{html.escape(report.report_id)}</span>"
                + (f"<a class='btn ghost small' href='/api/runs/{html.escape(run_id)}/report.md'>导出报告</a>"
                   if report.key_evidence else "")
                + "</div></div>"
                + fallback
                + "<div class='report-sec'><h4><span class='bar'></span>结论摘要</h4>"
                + f"<p class='lead-text'>{html.escape(report.executive_summary)}</p></div>"
                + "<div class='report-sec'><h4><span class='bar'></span>关键证据"
                + f" <span class='hint'>{len(report.key_evidence)} 条 · 点击引用可回溯原始返回</span></h4>"
                + f"<div class='ev-list'>{key_evidence}</div></div>"
                + "<div class='report-sec'><h4><span class='bar'></span>结论边界</h4>"
                + "<div class='stat-row'>"
                + f"<div class='stat'><b>{len(report.query_boundary_refs)}</b><small>查询边界</small></div>"
                + f"<div class='stat'><b>{len(report.counter_evidence)}</b><small>反证</small></div>"
                + f"<div class='stat'><b>{len(report.limitations)}</b><small>限制</small></div>"
                + "</div>"
                + (f"<ul class='limit-list'>{limit_items}</ul>" if limit_items else "")
                + (f"<h4><span class='bar'></span>反证（不支持当前结论的观察）</h4>"
                   f"<ul class='limit-list'>{counter_items}</ul>" if counter_items else "")
                + "</div>"
                + plan_html
                + "</div>"
            )
        else:
            report_html = (
                "<div class='card' style='margin-top:14px'><h2>研判报告</h2>"
                "<p class='muted'>尚未发布（运行未完成或失败）</p></div>"
            )

        verdict_chip = "<span class='muted'>调查中</span>"
        if report is not None:
            key = report.verdict.level.value
            verdict_chip = (
                f"<span class='pill {pages.VERDICT_PILL.get(key, 'muted')}'>"
                f"{html.escape(pages.VERDICT_ZH.get(key, key))}</span>"
                f" <span class='pill muted'>{html.escape(pages.PUBLICATION_ZH.get(report.publication_status, report.publication_status))}</span>"
            )
        metrics = (
            "<div class='card'><h2>案件档案</h2>"
            + f"<div class='metric'><small>当前结论</small><b>{verdict_chip}</b></div>"
            f"<div class='metric'><small>运行</small><b class='mono'>{html.escape(run_id)}</b></div>"
            f"<div class='metric'><small>案件</small><b class='mono'>{html.escape(trajectory.case_id)}</b></div>"
            f"<div class='metric'><small>状态</small><b>{html.escape(pages.STATUS_ZH.get(status, status))}</b></div>"
            "<div class='metric'><small>轮次 / 事件</small><b data-metric='rounds'>"
            + str(len(trajectory.rounds)) + " / " + str(trajectory.totals.get("events", 0))
            + "</b></div>"
            + f"<div class='metric' style='display:none'><small>事件</small>"
            f"<b data-metric='events'>{trajectory.totals.get('events', 0)}</b></div>"
            "<div class='metric'><small>重试</small><b>" + str(trajectory.totals.get("retries", 0)) + "</b></div>"
            + "<div class='metric'><small>Token（输入 / 输出）</small><b data-metric='tokens'>"
            + html.escape(fmt_token_pair(trajectory.totals.get("token_usage", {})))
            + "</b></div></div>"
        )

        error_event = None
        for event in reversed(investigation.events):
            if event.event_type == "error":
                error_event = event
                break
        error_message = str((error_event.details or {}).get("error_message") or "") if error_event else ""
        traceback_text = str((error_event.details or {}).get("exception_traceback") or "") if error_event else ""
        # Awaiting approval renders the decision card inline: the operator must
        # be able to decide without leaving the live investigation view.
        inline_approval = ""
        if status == "awaiting_approval" and approval_service is not None:
            pending = next(
                (item for item in approval_service.list_pending() if item.run_id == run_id),
                None,
            )
            if pending is not None:
                inline_approval = pages.approval_card_html(
                    pending, inline=True
                )

        banner = ""
        if status == "awaiting_approval":
            banner = ("<div class='banner violet'>⏸ 处置方案等待人工审批 · "
                      "下方流程中可直接决策</div>")
        elif status == "failed":
            banner = (
                "<div class='banner red' style='align-items:flex-start;flex-direction:column;gap:6px'>"
                "<div style='display:flex;gap:10px;align-items:center;width:100%'>"
                "✕ 调查失败 · <span class='mono'>" + html.escape(run.error_type or "")
                + "</span><span class='muted' style='color:inherit;font-weight:400'>"
                + html.escape(error_message[:120]) + "</span>"
                + "<button class='btn small' style='margin-left:auto' onclick='"
                + "fetch(\'/api/runs/" + html.escape(run_id) + "/replay\',{method:\'POST\'})"
                + ".then(r=>r.json()).then(b=>{location.href=\'/workbench/runs/\'+b.run_id})'"
                + ">重新调查</button></div>"
                + ("".join(
                    "<details style='margin-top:6px'><summary class='mono' style='cursor:pointer'>"
                    "查看完整堆栈</summary><pre style='white-space:pre-wrap;overflow-wrap:anywhere;"
                    "font:10.5px/1.5 Consolas,monospace;margin-top:6px;max-height:260px;overflow:auto'>"
                    + html.escape(traceback_text[-2000:]) + "</pre></details>"
                  ) if traceback_text else "")
                + "</div>"
            )

        # Pipeline bar carries the stage order + per-stage state so the live
        # stream can advance it (done / current / upcoming).
        stages = [("intake", "接入"), ("plan", "规划"), ("execute", "执行"), ("gate", "证据门"),
                  ("compose", "报告"), ("advise", "处置"), ("approve", "审批"), ("done", "完成")]
        reached = stage_reached(run.stage) or current_node(run)
        # The live stream reports run *stages*, the bar is indexed by pipeline
        # *nodes*: publish the mapping so the client can advance it correctly.
        stage_node_map = {
            "queued": "intake", "initializing": "intake", "investigating": "execute",
            "judgment": "gate", "reporting": "compose", "approval": "approve",
            "response_advisory": "advise", "publishing": "done", "published": "done",
            "advised": "done",
        }
        order = [name for name, _ in stages]
        idx = order.index(reached) if reached in order else -1
        pipeline_html = (
            f"<div id='pipeline' data-order='{','.join(order)}' "
            f"data-map='{json.dumps(stage_node_map)}' "
            "style='display:flex;gap:6px;flex-wrap:wrap'>"
            + "".join(
                f"<span class='pill {'ok' if i < idx else ('violet' if i == idx else 'muted')}' "
                f"data-stage='{name}'>{label}</span>"
                for i, (name, label) in enumerate(stages)
            )
            + "</div>"
        )

        # Boundary / budget rejections are the strongest prompt-quality signal:
        # aggregate them so "the model kept hitting a wall" is visible at a glance.
        rejections: dict[tuple[str, str], int] = {}
        for event in investigation.events:
            details = event.details or {}
            if details.get("kind") in ("tool_error",) or details.get("error_type") == "BoundaryDenied":
                key = (str(details.get("tool_name") or "—"), str(details.get("error_code") or "拒绝"))
                rejections[key] = rejections.get(key, 0) + 1
        rejections_html = ""
        if rejections:
            rows = "".join(
                f"<tr><td>{html.escape(pages.tool_zh(tool))}</td>"
                f"<td>{count} 次</td>"
                f"<td class='muted'>{html.escape(pages.DENY_REASON_ZH.get(code, code))}</td></tr>"
                for (tool, code), count in sorted(rejections.items(), key=lambda kv: -kv[1])
            )
            total_denied = sum(rejections.values())
            rejections_html = (
                "<div class='card' style='padding:12px 16px'><h2>被拒的查询 "
                f"<span class='hint'>共 {total_denied} 次被权限或预算挡下，模型据此调整了调查策略</span></h2>"
                "<table><thead><tr><th>能力</th><th>次数</th><th>原因</th></tr></thead>"
                f"<tbody>{rows}</tbody></table></div>"
            )

        snapshot_last_seq = max((e.sequence for e in investigation.events), default=0)
        return pages.render_run(
            run_id=html.escape(run_id),
            last_seq=snapshot_last_seq,
            rounds_count=len(trajectory.rounds),
            events_count=trajectory.totals.get("events", 0),
            token_usage=trajectory.totals.get("token_usage", {}),
            status=html.escape(status),
            case_id=html.escape(trajectory.case_id),
            rounds_html=rounds_html or "<p class='muted'>尚无轮次事件</p>",
            phases_html=phases_html or "<p class='muted'>无</p>",
            knowledge_html=knowledge_html,
            report_html=report_html,
            metrics=metrics,
            banner=banner,
            pipeline_html=pipeline_html,
            inline_approval=inline_approval,
            rejections_html=rejections_html,
        )

    def stage_reached(stage: str) -> str:
        """Map a run stage onto the farthest pipeline node reached."""

        return {
            "queued": "intake", "initializing": "intake", "investigating": "execute",
            "judgment": "gate", "reporting": "compose", "approval": "approve",
            "response_advisory": "advise", "publishing": "done", "published": "done",
            "advised": "done",
        }.get(stage, "")

    def current_node(run) -> str:
        mapping = {"initializing": "intake", "investigating": "plan", "judgment": "gate",
                   "reporting": "compose", "approval": "approve", "response_advisory": "advise",
                   "publishing": "done", "published": "done", "queued": "intake"}
        return mapping.get(run.stage, "")

    return app
