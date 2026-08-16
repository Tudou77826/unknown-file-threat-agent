"""Feature 13 — Single-Host Investigation Boundary acceptance tests.

Covers the pre-call authorization codes, post-execution result validation,
entity exploration authorization, cross-host clue handling, server-side tenant
injection and the "every tool passes the same boundary port" guarantee.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from threat_agent.bootstrap.settings import AppSettings
from threat_agent.case_management import (
    SingleHostBoundaryPolicy,
    initialize_state,
)
from threat_agent.contracts import (
    BoundaryDenied,
    DatasetManifest,
    InvestigationToolLedger,
    Scope,
    ToolRuntimeContext,
)
from threat_agent.data_foundation import (
    BatchIngestionService,
    ReferenceEventParser,
    SQLiteActivityQueryAdapter,
    SQLiteActivityStore,
)
from threat_agent.judgment import (
    BoundaryViolationError,
    InvestigationToolGateway,
    JudgmentGraph,
)
from threat_agent.judgment.application.data_tool_planner import investigation_tools
from threat_agent.judgment.domain.models import DataToolRequest, FinishRequest

NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)
TENANT = "tenant-a"
CASE = "case-a"
RUN = "run-a"
WINDOW_START = datetime(2026, 4, 23, tzinfo=timezone.utc)
WINDOW_END = datetime(2026, 4, 24, tzinfo=timezone.utc)
ENDPOINT = "endpoint:203.0.113.5:443"


def _seed(tmp_path: Path) -> SQLiteActivityStore:
    """Two hosts in one tenant sharing one external endpoint."""

    store = SQLiteActivityStore(tmp_path / "activities.sqlite")
    parser = ReferenceEventParser()
    manifest = DatasetManifest(
        tenant_id=TENANT, dataset_id="dataset", dataset_version="1", batch_id="batch",
        source_system="reference", connector_version="1", parser_name=parser.name,
        parser_version=parser.version,
    )
    events = [
        {
            "event_id": "p1", "event_type": "process_exec", "domain": "process",
            "source_system": "edr-process", "observed_at": "2026-04-23T03:20:44Z",
            "host_id": "host-1", "subject_refs": ["process:host-1:10:1776914444000"],
            "data": {"process_ref": "process:host-1:10:1776914444000", "executable": "/tmp/a"},
        },
        {
            "event_id": "n1", "event_type": "network_connection", "domain": "network",
            "source_system": "edr-network", "observed_at": "2026-04-23T03:21:44Z",
            "host_id": "host-1",
            "subject_refs": ["process:host-1:10:1776914444000", ENDPOINT],
            "data": {"process_ref": "process:host-1:10:1776914444000", "protocol": "tcp"},
        },
        {
            "event_id": "p2", "event_type": "process_exec", "domain": "process",
            "source_system": "edr-process", "observed_at": "2026-04-23T03:22:44Z",
            "host_id": "host-2", "subject_refs": ["process:host-2:20:1776914456000"],
            "data": {"process_ref": "process:host-2:20:1776914456000", "executable": "/tmp/b"},
        },
        {
            "event_id": "n2", "event_type": "network_connection", "domain": "network",
            "source_system": "edr-network", "observed_at": "2026-04-23T03:23:44Z",
            "host_id": "host-2",
            "subject_refs": ["process:host-2:20:1776914456000", ENDPOINT],
            "data": {"process_ref": "process:host-2:20:1776914456000", "protocol": "tcp"},
        },
    ]
    BatchIngestionService(store, parser).ingest_payloads(manifest, events, ingested_at=NOW)
    return store


def _context(**scope_overrides) -> ToolRuntimeContext:
    scope_fields: dict = {
        "host_ids": ["host-1"], "start_time": WINDOW_START, "end_time": WINDOW_END,
    }
    scope_fields.update(scope_overrides)
    return ToolRuntimeContext(
        tenant_id=TENANT, case_id=CASE, run_id=RUN, scope=Scope(**scope_fields),
    )


def _policy() -> SingleHostBoundaryPolicy:
    return SingleHostBoundaryPolicy(tenant_id=TENANT, case_id=CASE, run_id=RUN)


def _gateway(store, boundary=None, events=None):
    return InvestigationToolGateway(
        store,
        SQLiteActivityQueryAdapter(store),
        boundary or _policy(),
        event_sink=(lambda kind, message, details=None: events.append((kind, message, details)))
        if events is not None else None,
    )


# ---------------------------------------------------------------------------
# Pre-call authorization: host / time / domain / entity / reference codes
# ---------------------------------------------------------------------------

def test_other_host_is_denied_before_the_data_layer(tmp_path: Path):
    store = _seed(tmp_path)
    try:
        gateway = _gateway(store)
        with pytest.raises(BoundaryViolationError) as denial:
            gateway.invoke(
                "query_process_activities", {"host_refs": ["host-2"]},
                _context(), InvestigationToolLedger(),
            )
        assert denial.value.code == "host_out_of_scope"
        assert denial.value.denial.host_refs == ["host-2"]
    finally:
        store.close()


def test_time_outside_window_is_denied(tmp_path: Path):
    store = _seed(tmp_path)
    try:
        gateway = _gateway(store)
        with pytest.raises(BoundaryViolationError) as denial:
            gateway.invoke(
                "query_process_activities",
                {"start_time": (WINDOW_START - timedelta(hours=1)).isoformat()},
                _context(), InvestigationToolLedger(),
            )
        assert denial.value.code == "time_out_of_scope"
        # Naive timestamps (no timezone) must deny cleanly instead of raising
        # a naive/aware TypeError during comparison.
        with pytest.raises(BoundaryViolationError) as naive_denial:
            gateway.invoke(
                "query_process_activities",
                {"start_time": "2026-04-22T00:00:00"},
                _context(), InvestigationToolLedger(),
            )
        assert naive_denial.value.code == "time_out_of_scope"
    finally:
        store.close()


def test_domain_not_in_scope_is_denied(tmp_path: Path):
    store = _seed(tmp_path)
    try:
        gateway = _gateway(store)
        with pytest.raises(BoundaryViolationError) as denial:
            gateway.invoke(
                "query_network_activities", {},
                _context(allowed_domains=["process"]), InvestigationToolLedger(),
            )
        assert denial.value.code == "domain_out_of_scope"
    finally:
        store.close()


def test_scope_with_multiple_hosts_is_denied(tmp_path: Path):
    store = _seed(tmp_path)
    try:
        gateway = _gateway(store)
        with pytest.raises(BoundaryViolationError) as denial:
            gateway.invoke(
                "query_process_activities", {},
                _context(host_ids=["host-1", "host-2"]), InvestigationToolLedger(),
            )
        assert denial.value.code == "single_host_required"
    finally:
        store.close()


def test_explore_entity_requires_a_run_authorized_entity(tmp_path: Path):
    store = _seed(tmp_path)
    try:
        gateway = _gateway(store)
        ledger = InvestigationToolLedger()
        with pytest.raises(BoundaryViolationError) as denial:
            gateway.invoke(
                "explore_entity", {"entity_ref": "process:host-2:20:1776914456000"},
                _context(), ledger,
            )
        assert denial.value.code == "entity_not_authorized"

        # The alert-host process becomes explorable only after a query of this
        # run returned it.
        gateway.invoke("query_process_activities", {}, _context(), ledger)
        result = gateway.invoke(
            "explore_entity", {"entity_ref": "process:host-1:10:1776914444000"},
            _context(), ledger,
        )
        assert result.identity is not None
    finally:
        store.close()


def test_raw_and_metric_reference_codes(tmp_path: Path):
    store = _seed(tmp_path)
    try:
        gateway = _gateway(store)
        ledger = InvestigationToolLedger()
        with pytest.raises(BoundaryViolationError) as denial:
            gateway.invoke(
                "calculate_activity_metrics",
                {"operation": "process_tree", "activity_refs": ["activity-p1"]},
                _context(), ledger,
            )
        assert denial.value.code == "reference_not_authorized"
    finally:
        store.close()


def test_context_identity_mismatch_is_a_wiring_error(tmp_path: Path):
    store = _seed(tmp_path)
    try:
        gateway = _gateway(store)
        with pytest.raises(ValueError):
            gateway.invoke(
                "query_process_activities", {},
                ToolRuntimeContext(
                    tenant_id="evil-tenant", case_id=CASE, run_id=RUN,
                    scope=Scope(host_ids=["host-1"]),
                ),
                InvestigationToolLedger(),
            )
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Result validation and ledger containment
# ---------------------------------------------------------------------------

class _ValidatingBoundary:
    """Delegate to the real policy but fail validate_result for one tool."""

    def __init__(self, inner, fail_tool: str):
        self.inner = inner
        self.fail_tool = fail_tool

    def authorize_call(self, context, ledger, tool_name, arguments):
        self.inner.authorize_call(context, ledger, tool_name, arguments)

    def validate_result(self, context, ledger, tool_name, result):
        if tool_name == self.fail_tool:
            raise BoundaryViolationError(BoundaryDenied(
                code="host_out_of_scope", tool_name=tool_name,
                message="forced failure", host_refs=["host-2"],
            ))
        self.inner.validate_result(context, ledger, tool_name, result)


def test_failed_result_validation_never_reaches_ledger_or_traces(tmp_path: Path):
    store = _seed(tmp_path)
    try:
        events = []
        gateway = _gateway(store, boundary=_ValidatingBoundary(_policy(), "query_process_activities"), events=events)
        ledger = InvestigationToolLedger()
        with pytest.raises(BoundaryViolationError):
            gateway.invoke("query_process_activities", {}, _context(), ledger)
        assert ledger.query_results == []
        assert ledger.traces == []
        assert ledger.authorized_activity_refs == []
        denial_events = [item for item in events if item[0] == "tool_error"]
        assert denial_events, "boundary denial must be observable"
        assert denial_events[0][2]["error_code"] == "host_out_of_scope"
    finally:
        store.close()


def test_shared_entity_timeline_excludes_other_hosts(tmp_path: Path):
    store = _seed(tmp_path)
    try:
        gateway = _gateway(store)
        ledger = InvestigationToolLedger()
        gateway.invoke("query_network_activities", {}, _context(), ledger)
        result = gateway.invoke("explore_entity", {"entity_ref": ENDPOINT}, _context(), ledger)
        # Both hosts' processes connect to this endpoint, but the timeline may
        # only carry alert-host activities.
        hosts = {activity.host_ref for activity in result.timeline}
        assert hosts <= {"host-1"}
        # The host-2 relation endpoint is reduced to an identifier-only clue.
        assert result.out_of_scope_relations, "cross-host relation must surface as a clue"
        clue = result.out_of_scope_relations[0]
        assert clue.reason == "host_out_of_scope"
        clue_payload = clue.model_dump()
        assert set(clue_payload) == {"relation_id", "other_endpoint_ref", "reason"}
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Every registered tool passes the same port
# ---------------------------------------------------------------------------

class _RecordingBoundary:
    def __init__(self, inner):
        self.inner = inner
        self.authorized: list[str] = []
        self.validated: list[str] = []

    def authorize_call(self, context, ledger, tool_name, arguments):
        self.authorized.append(tool_name)
        self.inner.authorize_call(context, ledger, tool_name, arguments)

    def validate_result(self, context, ledger, tool_name, result):
        self.validated.append(tool_name)
        self.inner.validate_result(context, ledger, tool_name, result)


def test_every_tool_passes_the_boundary_port_and_unknown_tools_are_rejected(tmp_path: Path):
    store = _seed(tmp_path)
    try:
        recording = _RecordingBoundary(_policy())
        gateway = _gateway(store, boundary=recording)
        ledger = InvestigationToolLedger()

        gateway.invoke("query_process_activities", {}, _context(), ledger)
        gateway.invoke("query_network_activities", {}, _context(), ledger)
        ref = ledger.authorized_activity_refs[0]
        gateway.invoke("explore_entity", {"entity_ref": ENDPOINT}, _context(), ledger)
        gateway.invoke("get_raw_records", {"activity_refs": [ref]}, _context(), ledger)
        gateway.invoke(
            "calculate_activity_metrics",
            {"operation": "process_tree", "activity_refs": [ref]}, _context(), ledger,
        )
        exercised = {
            "query_process_activities", "query_network_activities", "explore_entity",
            "get_raw_records", "calculate_activity_metrics",
        }
        assert exercised <= set(recording.authorized)
        assert exercised <= set(recording.validated)

        with pytest.raises(KeyError):
            gateway.invoke("request_scope_expansion", {}, _context(), ledger)

        # A denying port blocks the remaining domain tools too: none of the
        # registered tools can bypass the port.
        class _DenyAll:
            def authorize_call(self, context, ledger, tool_name, arguments):
                raise BoundaryViolationError(BoundaryDenied(
                    code="host_out_of_scope", tool_name=tool_name, message="denied",
                ))

            def validate_result(self, context, ledger, tool_name, result):
                raise AssertionError("validate must not run after authorize denied")

        deny_gateway = _gateway(store, boundary=_DenyAll())
        for tool in InvestigationToolGateway.tool_names:
            if tool in {"get_raw_records", "calculate_activity_metrics"}:
                arguments = {"activity_refs": [ref], "operation": "process_tree"}
            elif tool == "explore_entity":
                arguments = {"entity_ref": ENDPOINT}
            else:
                arguments = {}
            with pytest.raises(BoundaryViolationError):
                deny_gateway.invoke(tool, arguments, _context(), InvestigationToolLedger())
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Graph-level: server tenant injection, budget, structured denial feedback
# ---------------------------------------------------------------------------

class _ScriptedPlanner:
    uses_data_tools = True

    def __init__(self, actions):
        self.actions = list(actions)

    def plan(self, _state):
        if not self.actions:
            return [FinishRequest(objective="所有动作已执行完毕，结束调查")]
        return [self.actions.pop(0)]


class _SpyGateway:
    def __init__(self):
        self.calls: list[ToolRuntimeContext] = []

    def invoke(self, tool_name, arguments, context, ledger, **_kwargs):
        self.calls.append(context)
        raise BoundaryViolationError(BoundaryDenied(
            code="host_out_of_scope", tool_name=tool_name,
            message="请求主机超出唯一告警主机边界", host_refs=["host-2"],
        ))


def _graph_state():
    state = initialize_state({
        "File_id": "file-a", "File_hash": "a" * 64, "File_path": "/tmp/a",
        "Sub_asset": "host-1", "tenant_id": "spoofed-tenant", "run_id": "spoofed-run",
    })
    state.scope = Scope(host_ids=["host-1"], start_time=WINDOW_START, end_time=WINDOW_END)
    return state


def test_graph_uses_server_tenant_and_reports_structured_denials():
    spy = _SpyGateway()
    graph = JudgmentGraph(
        _ScriptedPlanner([DataToolRequest(
            tool_name="query_process_activities",
            objective="查询另一台主机的进程活动",
            arguments={"host_refs": ["host-2"]},
        )]),
        tenant_id="demo",
        run_id="run-1",
        data_tool_gateway=spy,
    )
    result = graph.run(_graph_state())
    # The alert payload (raw_input) must not override the server identity.
    assert spy.calls[0].tenant_id == "demo"
    assert spy.calls[0].run_id == "run-1"
    denied = [call for call in result.tool_calls if call.status == "denied"]
    assert denied and "host_out_of_scope" in (denied[0].error or "")
    trace = result.tool_ledger.traces[-1]
    assert trace.result_type == "ToolError"
    assert trace.result["error_code"] == "host_out_of_scope"
    assert result.finished


def test_tool_budget_is_enforced_without_invoking_the_gateway():
    spy = _SpyGateway()
    state = _graph_state()
    state.budget.max_tool_calls = 0
    graph = JudgmentGraph(
        _ScriptedPlanner([DataToolRequest(
            tool_name="query_process_activities",
            objective="一次超出调用预算的进程活动查询",
            arguments={},
        )]),
        tenant_id="demo",
        run_id="run-1",
        data_tool_gateway=spy,
    )
    result = graph.run(state)
    assert spy.calls == []
    assert any("budget" in (call.error or "").lower() for call in result.tool_calls)


# ---------------------------------------------------------------------------
# Intake and configuration
# ---------------------------------------------------------------------------

def test_intake_rejects_multi_host_and_missing_host():
    with pytest.raises(ValueError):
        initialize_state({
            "File_hash": "a" * 64, "File_path": "/tmp/a",
            "Sub_asset": ["host-1", "host-2"],
        })
    with pytest.raises(ValueError):
        initialize_state({"File_hash": "a" * 64, "File_path": "/tmp/a"})
    state = initialize_state({
        "File_hash": "a" * 64, "File_path": "/tmp/a", "Sub_asset": "host-1",
        "discovery_time": 1776914444221,
    })
    assert state.scope.host_ids == ["host-1"]
    # Intake anchors seed the authorized entity set.
    assert "host:host-1" in state.tool_ledger.authorized_entity_refs


def test_lookback_window_is_configurable():
    raw = {
        "File_hash": "a" * 64, "File_path": "/tmp/a", "Sub_asset": "host-1",
        "discovery_time": 1776914444221,
    }
    default_state = initialize_state(raw)
    six_hour_state = initialize_state(raw, lookback_hours=6)
    delta = six_hour_state.scope.start_time - default_state.scope.start_time
    assert delta == timedelta(hours=18)


def test_lookback_hours_setting_is_loaded_from_environment():
    settings = AppSettings.load(
        environ={"INVESTIGATION_LOOKBACK_HOURS": "48"},
        env_file=Path("nonexistent.env"),
    )
    assert settings.application.investigation_lookback_hours == 48.0


def test_planner_catalog_has_no_cross_host_tools():
    names = {tool.name for tool in investigation_tools()}
    assert "request_scope_expansion" not in names
    assert "finish_investigation" in names
