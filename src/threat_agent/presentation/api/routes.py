from __future__ import annotations

import html
import json
from typing import Any, Protocol

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

from ...contracts import InvestigationCreateRequest, InvestigationRunReadModel
from ..projection.case_projector import case_read_payload
from ..read_model.store import CaseReadStore
from ..read_model.demo_store import DemoComparisonStore
from .demo_page import render_demo_page


class DemoRunServicePort(Protocol):
    def start(self, dataset_id: str, profile_id: str) -> str: ...
    def get_investigation(self, run_id: str) -> InvestigationRunReadModel | None: ...


def create_app(
    store: CaseReadStore,
    demo_store: DemoComparisonStore | None = None,
    demo_run_service: DemoRunServicePort | None = None,
) -> FastAPI:
    app = FastAPI(title="Unknown File Threat Agent", version="1.0")

    def load(case_id: str, tenant_id: str):
        item = store.get(tenant_id, case_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return item

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/cases/{case_id}")
    def get_case(case_id: str, x_tenant_id: str = Header(default="default")) -> dict:
        return case_read_payload(load(case_id, x_tenant_id))

    @app.get("/api/demo/{dataset_id}")
    def get_demo(dataset_id: str) -> dict:
        item = demo_store.get(dataset_id) if demo_store is not None else None
        if item is None:
            raise HTTPException(status_code=404, detail="Demo comparison not found")
        return item.model_dump(mode="json")

    @app.post("/api/investigations", status_code=202)
    def start_investigation(payload: InvestigationCreateRequest) -> dict[str, str]:
        if demo_run_service is None:
            raise HTTPException(status_code=503, detail="Investigation runner is not configured")
        try:
            run_id = demo_run_service.start(
                payload.reference_dataset_id, payload.profile_id
            )
        except KeyError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        return {
            "run_id": run_id,
            "status": "queued",
            "location": f"/api/investigations/{run_id}",
        }

    @app.get("/api/investigations/{run_id}")
    def get_investigation(run_id: str) -> dict[str, Any]:
        if demo_run_service is None:
            raise HTTPException(status_code=503, detail="Investigation runner is not configured")
        item = demo_run_service.get_investigation(run_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Investigation run not found")
        return item.model_dump(mode="json")

    @app.get("/demo/{dataset_id}", response_class=HTMLResponse)
    def demo_page(dataset_id: str) -> str:
        item = demo_store.get(dataset_id) if demo_store is not None else None
        if item is None:
            raise HTTPException(status_code=404, detail="Demo comparison not found")
        return render_demo_page(item)

    @app.get("/cases/{case_id}", response_class=HTMLResponse)
    def case_page(case_id: str, x_tenant_id: str = Header(default="default")) -> str:
        item = load(case_id, x_tenant_id)
        payload = case_read_payload(item)
        verdict = payload.get("verdict") or {}
        response = payload.get("response_plan") or {}
        facts = "".join(
            f"<li>{html.escape(str(value.get('statement', '')))}</li>"
            for value in payload["facts"]
        ) or "<li>No confirmed facts</li>"
        findings = "".join(
            f"<li>{html.escape(str(value.get('statement', '')))}</li>"
            for value in payload["findings"]
        ) or "<li>No findings</li>"
        actions = "".join(
            f"<li><strong>{html.escape(str(value.get('action_type', '')))}</strong>: "
            f"{html.escape(str(value.get('rationale', '')))}</li>"
            for value in response.get("actions", [])
        ) or "<li>No response actions</li>"
        raw = html.escape(json.dumps(payload, ensure_ascii=False, indent=2))
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Case {html.escape(case_id)}</title>
<style>
body{{font:15px/1.5 system-ui,sans-serif;margin:0;background:#f4f7fb;color:#172033}}
main{{max-width:1100px;margin:auto;padding:32px}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}}
section{{background:white;border:1px solid #dfe6ef;border-radius:10px;padding:18px;margin-bottom:16px}}
.level{{font-size:24px;font-weight:700}} .muted{{color:#607086}} pre{{white-space:pre-wrap;overflow-wrap:anywhere}}
</style></head><body><main>
<p class="muted">Security case · {html.escape(item.lifecycle_status)}</p>
<h1>{html.escape(case_id)}</h1>
<div class="grid"><section><h2>Verdict</h2><div class="level">{html.escape(str(verdict.get('level', 'pending')))}</div>
<p>{html.escape(str(verdict.get('summary', 'No verdict published')))}</p></section>
<section><h2>Response</h2><div class="level">{html.escape(str(response.get('status', 'not generated')))}</div><ul>{actions}</ul></section></div>
<div class="grid"><section><h2>Facts</h2><ul>{facts}</ul></section><section><h2>Findings</h2><ul>{findings}</ul></section></div>
<section><details><summary>Structured case record</summary><pre>{raw}</pre></details></section>
</main></body></html>"""

    return app
