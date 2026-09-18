"""Feature 15 canonical framework-middleware runtime.

Covers the pieces users perceive on the demo page:

- ``MiddlewareJudgmentRunner`` completes a scripted investigation through
  the CaseGraph-compatible subgraph: typed ledger merged back, report
  published (fallback path with a deliberately ungrounded stub draft),
  runtime events emitted;
- budget exhaustion inside the runner degrades to a report instead of
  failing the run;
- the API starts the one supported runtime and rejects legacy selectors.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from langchain_core.language_models.fake_chat_models import (
    FakeListChatModel,
    GenericFakeChatModel,
)
from langchain_core.messages import AIMessage
from langchain_core.messages.tool import ToolMessage

from middleware_harness import RUN, TENANT, ScriptedModel, seed_store
from threat_agent.bootstrap.middleware_runtime import MiddlewareJudgmentRunner
from threat_agent.case_management import SingleHostBoundaryPolicy, initialize_state
from threat_agent.contracts import (
    InvestigationRunReadModel,
    Scope,
    ToolRuntimeContext,
)
from threat_agent.data_foundation import SQLiteInvestigationDataAdapter
from threat_agent.judgment import InvestigationToolGateway
from threat_agent.judgment.application.report_draft import ReportDraft
from threat_agent.contracts.investigation import CandidateVerdict
from threat_agent.presentation import InMemoryCaseReadStore, InMemoryDemoComparisonStore
from threat_agent.presentation.api.routes import create_app

SCRIPT = [
    ("query_process_activities", {}),
    ("query_network_activities", {}),
]


class _StubComposer:
    """Composer whose draft cites a nonexistent reference: the grounding
    validator must reject it and the pipeline must publish the fallback."""

    model_name = "stub-composer"

    def compose_draft(self, state):
        return ReportDraft(
            verdict=CandidateVerdict(
                level="confirmed_malicious",
                threat_type="backdoor_c2",
                summary="stub draft",
                supporting_refs=["activity-does-not-exist"],
            ),
            executive_summary="stub draft",
        )

    def rejudge(self, state, previous_draft, issues, *, attempt):
        return previous_draft


def _runner(store, state, model, summarizer, budget, events):
    policy = SingleHostBoundaryPolicy(
        tenant_id=TENANT, case_id=state.case_id, run_id=RUN
    )
    context = ToolRuntimeContext(
        tenant_id=TENANT, case_id=state.case_id, run_id=RUN,
        scope=Scope(host_ids=["host-1"]),
    )
    return MiddlewareJudgmentRunner(
        model=model,
        summarizer_model=summarizer,
        gateway=InvestigationToolGateway(
            SQLiteInvestigationDataAdapter(store), policy
        ),
        boundary_policy=policy,
        context=context,
        ledger=state.tool_ledger,
        case_budget=budget,
        report_composer=_StubComposer(),
        emit=lambda kind, message, details=None: events.append(
            (kind, message, details or {})
        ),
        context_window_tokens=800,
        recursion_limit=100,
    )


def _state():
    state = initialize_state({
        "File_id": "file-a", "File_hash": "a" * 64, "File_path": "/tmp/a",
        "Sub_asset": "host-1",
    })
    state.scope = Scope(host_ids=["host-1"])
    return state


def _script_model():
    return ScriptedModel(messages=iter([
        *[
            AIMessage(content="", tool_calls=[{
                "name": name, "args": dict(arguments),
                "id": f"call-{index}", "type": "tool_call",
            }])
            for index, (name, arguments) in enumerate(SCRIPT)
        ],
        AIMessage(content="done"),
    ]))


def test_runner_completes_and_publishes_fallback_report(tmp_path: Path):
    store = seed_store(tmp_path)
    try:
        state = _state()
        events: list = []
        runner = _runner(
            store, state, _script_model(), FakeListChatModel(responses=["摘要"]),
            state.budget, events,
        )
        result = runner.run(state)
        assert result.finished is True
        # Typed ledger merged back into the returned state.
        assert [t.tool_name for t in result.tool_ledger.traces] == [
            name for name, _ in SCRIPT
        ]
        # Ungrounded stub draft must degrade to the fallback publication.
        assert result.investigation_report is not None
        assert result.investigation_report.verdict.level.value == "insufficient_evidence"
        # Runtime events are observable.
        kinds = [kind for kind, _message, _details in events]
        assert "graph" in kinds
        startup = next(
            details for kind, _m, details in events
            if kind == "graph"
            and details.get("orchestration") == "framework_middleware"
        )
        assert "BudgetMiddleware" in startup["middlewares"]
    finally:
        store.close()


def test_runner_degrades_on_budget_exhaustion_instead_of_failing(tmp_path: Path):
    store = seed_store(tmp_path)
    try:
        state = _state()
        state.budget.max_iterations = 1
        state.budget.max_tool_calls = 1
        events: list = []
        runner = _runner(
            store, state, _script_model(), FakeListChatModel(responses=["摘要"]),
            state.budget, events,
        )
        result = runner.run(state)
        assert result.finished is True
        assert result.investigation_report is not None
        assert len(result.tool_ledger.traces) == 1
        messages = [m for kind, m, d in events if kind == "graph" and d.get("degraded")]
        assert messages, "the degradation ending must be observable in events"
    finally:
        store.close()


def test_boundary_denials_surface_as_tool_error_events(tmp_path: Path):
    store = seed_store(tmp_path)
    try:
        state = _state()
        events: list = []
        model = ScriptedModel(messages=iter([
            AIMessage(content="", tool_calls=[{
                "name": "query_process_activities",
                "args": {"host_refs": ["host-2"]}, "id": "c1", "type": "tool_call",
            }]),
            AIMessage(content="done"),
        ]))
        runner = _runner(
            store, state, model, FakeListChatModel(responses=["摘要"]),
            state.budget, events,
        )
        result = runner.run(state)
        assert result.finished is True
        assert result.tool_ledger.traces == []
        denials = [
            details for kind, _m, details in events
            if kind == "tool_error" and details.get("error_type") == "BoundaryDenied"
        ]
        assert denials and denials[0]["error_code"] == "host_out_of_scope"
    finally:
        store.close()


class _FakeRunService:
    def __init__(self):
        self.started: list[tuple[str, str]] = []

    def start(self, dataset_id, profile_id):
        self.started.append((dataset_id, profile_id))
        return "run-1"

    def get_investigation(self, run_id):
        from threat_agent.contracts import InvestigationRun

        return InvestigationRunReadModel(
            run=InvestigationRun(
                tenant_id=TENANT, case_id="case-1", run_id=run_id,
                source_identity="persistent-demo-run-service/framework-middleware",
                status="completed", stage="done",
                graph_thread_id=f"{TENANT}/case-1/{run_id}",
            ),
            reference_dataset_id="ds",
            profile_id="l3",
        )


def test_api_starts_the_framework_runtime_and_rejects_legacy_selector():
    service = _FakeRunService()
    comparisons = InMemoryDemoComparisonStore({})
    app = create_app(InMemoryCaseReadStore(), comparisons, service)
    client = TestClient(app)

    response = client.post("/api/investigations", json={
        "reference_dataset_id": "ds", "profile_id": "l3",
    })
    assert response.status_code == 202
    assert service.started == [("ds", "l3")]

    legacy_selector = client.post("/api/investigations", json={
        "reference_dataset_id": "ds", "profile_id": "l3", "runtime": "middleware",
    })
    assert legacy_selector.status_code == 422

    detail = client.get("/api/investigations/run-1")
    assert detail.status_code == 200
    assert "runtime" not in detail.json()
