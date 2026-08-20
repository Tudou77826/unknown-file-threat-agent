from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from threat_agent.case_management import SingleHostBoundaryPolicy, initialize_state
from threat_agent.contracts import (
    CandidateVerdict,
    DatasetManifest,
    InvestigationToolLedger,
    ReportStatement,
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
    ReportGroundingValidator,
    ReportRepairCoordinator,
    StructuredReportComposer,
)
from threat_agent.judgment.application.data_tool_planner import DataToolSelection, StructuredDataToolPlanner
from threat_agent.judgment.application.report_draft import ReportDraft
from threat_agent.judgment.domain.models import DataToolRequest, FinishRequest, ToolCall


NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)


def _state():
    return initialize_state({
        "File_id": "file-a", "File_hash": "a" * 64, "File_path": "/tmp/a",
        "Sub_asset": "host-1", "tenant_id": "tenant-a", "run_id": "run-a",
    })


def _store(tmp_path: Path) -> SQLiteActivityStore:
    store = SQLiteActivityStore(tmp_path / "activities.sqlite")
    parser = ReferenceEventParser()
    manifest = DatasetManifest(
        tenant_id="tenant-a", dataset_id="dataset", dataset_version="1", batch_id="batch",
        source_system="reference", connector_version="1", parser_name=parser.name,
        parser_version=parser.version,
    )
    events = [
        {
            "event_id": "process-1", "event_type": "process_exec", "domain": "process",
            "source_system": "edr-process", "observed_at": "2026-04-23T03:20:44Z",
            "host_id": "host-1", "subject_refs": ["process:host-1:10:1776914444000"],
            "data": {"process_ref": "process:host-1:10:1776914444000", "executable": "/tmp/a"},
        },
        {
            "event_id": "network-1", "event_type": "network_connection", "domain": "network",
            "source_system": "edr-network", "observed_at": "2026-04-23T03:21:44Z",
            "host_id": "host-1", "subject_refs": ["process:host-1:10:1776914444000", "endpoint:203.0.113.5:443"],
            "data": {"process_ref": "process:host-1:10:1776914444000", "protocol": "tcp"},
        },
    ]
    BatchIngestionService(store, parser).ingest_payloads(manifest, events, ingested_at=NOW)
    return store


def _context() -> ToolRuntimeContext:
    return ToolRuntimeContext(
        tenant_id="tenant-a", case_id="case-a", run_id="run-a",
        scope=Scope(host_ids=["host-1"], start_time=datetime(2026, 4, 23, tzinfo=timezone.utc),
                    end_time=datetime(2026, 4, 24, tzinfo=timezone.utc)),
    )


def _boundary() -> SingleHostBoundaryPolicy:
    return SingleHostBoundaryPolicy(tenant_id="tenant-a", case_id="case-a", run_id="run-a")


def test_gateway_exposes_domain_data_tools_and_routes_typed_query(tmp_path: Path):
    store = _store(tmp_path)
    try:
        emitted = []
        gateway = InvestigationToolGateway(
            store,
            SQLiteActivityQueryAdapter(store),
            _boundary(),
            event_sink=lambda kind, message, details=None: emitted.append(
                (kind, message, details)
            ),
        )
        ledger = InvestigationToolLedger()
        assert gateway.tool_names == (
            "query_process_activities", "query_network_activities", "query_socket_activities",
            "query_file_activities", "query_service_activities", "query_package_activities",
            "query_asset_activities", "explore_entity", "get_raw_records",
            "calculate_activity_metrics",
        )
        result = gateway.invoke(
            "query_process_activities",
            {"operations": ["execute"]},
            _context(), ledger,
        )
        assert result.execution_boundary.returned_count == 1
        assert ledger.authorized_activity_refs == [result.activities[0].activity_id]
        assert result.interface_definition.interface_id == "activity-query/process"
        assert emitted[0][0] == "tool"
        assert emitted[0][2]["tool_name"] == "query_process_activities"
        assert emitted[0][2]["returned_count"] == 1
        assert emitted[0][2]["duration_ms"] >= 0
    finally:
        store.close()


def test_gateway_rejects_out_of_scope_host(tmp_path: Path):
    store = _store(tmp_path)
    try:
        gateway = InvestigationToolGateway(store, SQLiteActivityQueryAdapter(store), _boundary())
        with pytest.raises(BoundaryViolationError) as denial:
            gateway.invoke(
                "query_process_activities", {"host_refs": ["host-2"]},
                _context(), InvestigationToolLedger(),
            )
        assert denial.value.code == "host_out_of_scope"
    finally:
        store.close()


def test_raw_and_metric_tools_require_activity_returned_in_same_run(tmp_path: Path):
    store = _store(tmp_path)
    try:
        gateway = InvestigationToolGateway(store, SQLiteActivityQueryAdapter(store), _boundary())
        ledger = InvestigationToolLedger()
        with pytest.raises(BoundaryViolationError) as denial:
            gateway.invoke(
                "get_raw_records", {"activity_refs": ["activity-process-1"]}, _context(), ledger
            )
        assert denial.value.code == "reference_not_authorized"
        query = gateway.invoke(
            "query_network_activities", {}, _context(), ledger
        )
        ref = query.activities[0].activity_id
        raw = gateway.invoke("get_raw_records", {"activity_refs": [ref]}, _context(), ledger)
        assert raw.records[0].payload["event_type"] == "network_connection"
        # Bare business field names fall back to the event envelope's data
        # section instead of silently returning an empty payload.
        projected = gateway.invoke(
            "get_raw_records",
            {"activity_refs": [ref], "field_paths": ["protocol", "data.process_ref", "observed_at"]},
            _context(), ledger,
        )
        payload = projected.records[0].payload
        assert payload["protocol"] == "tcp"
        assert payload["data.process_ref"] == "process:host-1:10:1776914444000"
        assert "observed_at" in payload
        metrics = gateway.invoke(
            "calculate_activity_metrics",
            {"operation": "connection_pattern", "activity_refs": [ref]}, _context(), ledger,
        )
        assert metrics.metrics["endpoints"]["endpoint:203.0.113.5:443"]["connection_count"] == 1
        assert "verdict" not in metrics.model_dump()
    finally:
        store.close()


class _BoundModel:
    def __init__(self, schema, payload):
        self.schema = schema
        self.payload = payload

    def invoke(self, _messages):
        return self.payload[self.schema]


class _FakeModel:
    model_name = "fake-model"

    def __init__(self, payload):
        self.payload = payload

    def with_structured_output(self, schema, **_kwargs):
        return _BoundModel(schema, self.payload)

    def bind_tools(self, tools, **_kwargs):
        self.bound_tools = tools
        return self

    def invoke(self, _messages):
        return self.payload[AIMessage]


def test_data_tool_planner_can_only_select_domain_tools_or_actions():
    state = _state()
    model = _FakeModel({AIMessage: AIMessage(content="", tool_calls=[{
        "name": "query_process_activities",
        "args": {"entity_refs": ["process:host-1:10:1"]},
        "id": "call-native-1",
        "type": "tool_call",
    }])})
    planner = StructuredDataToolPlanner(model)
    actions = planner.plan(state)
    assert isinstance(actions, list) and len(actions) == 1
    action = actions[0]
    assert isinstance(action, DataToolRequest)
    assert action.tool_name == "query_process_activities"
    assert action.arguments["entity_refs"] == ["process:host-1:10:1"]
    assert action.tool_call_id == "call-native-1"
    schemas = {tool.name: tool.args_schema.model_json_schema() for tool in model.bound_tools}
    # Process tool exposes process fields only; no activity_type, no foreign fields.
    assert "entity_refs" in schemas["query_process_activities"]["properties"]
    assert "process_refs" in schemas["query_process_activities"]["properties"]
    assert "activity_type" not in schemas["query_process_activities"]["properties"]
    assert "endpoint_refs" not in schemas["query_process_activities"]["properties"]


def test_data_tool_planner_returns_all_planned_tool_calls_in_order():
    state = _state()
    model = _FakeModel({AIMessage: AIMessage(content="", tool_calls=[
        {"name": "query_process_activities", "args": {"host_refs": ["host-1"]}, "id": "call-1", "type": "tool_call"},
        {"name": "query_file_activities", "args": {"file_refs": ["file-a"]}, "id": "call-2", "type": "tool_call"},
    ])})
    planner = StructuredDataToolPlanner(model)
    actions = planner.plan(state)
    assert [a.tool_name for a in actions] == ["query_process_activities", "query_file_activities"]
    assert all(isinstance(a, DataToolRequest) for a in actions)
    assert [a.tool_call_id for a in actions] == ["call-1", "call-2"]


def test_data_tool_planner_orders_finish_last_and_finishes_without_tool_calls():
    state = _state()
    model = _FakeModel({AIMessage: AIMessage(content="", tool_calls=[
        {"name": "finish_investigation", "args": {"objective": "现有证据已经充分，可以结束调查"}, "id": "call-f", "type": "tool_call"},
        {"name": "query_process_activities", "args": {"host_refs": ["host-1"]}, "id": "call-q", "type": "tool_call"},
    ])})
    planner = StructuredDataToolPlanner(model)
    actions = planner.plan(state)
    assert isinstance(actions[-1], FinishRequest)
    assert isinstance(actions[0], DataToolRequest)

    model2 = _FakeModel({AIMessage: AIMessage(content="", tool_calls=[])})
    actions2 = StructuredDataToolPlanner(model2).plan(state)
    assert len(actions2) == 1 and isinstance(actions2[0], FinishRequest)


def test_data_tool_planner_appends_round_reminder_after_threshold():
    state = _state()
    state.budget.iterations_used = 16
    state.budget.max_iterations = 35
    model = _FakeModel({AIMessage: AIMessage(content="", tool_calls=[])})
    planner = StructuredDataToolPlanner(model)
    messages = planner._messages(state)
    # The reminder rides the trailing dynamic message, which must NOT be a
    # system message: qwen/DashScope allows only one leading system message.
    reminder = [m for m in messages if isinstance(m, HumanMessage) and "system_remind" in m.content]
    assert len(reminder) == 1
    assert "16/35" in reminder[0].content


def test_grounding_validator_locates_unknown_refs_scope_and_candidate_relations(tmp_path: Path):
    store = _store(tmp_path)
    try:
        state = _state()
        state.scope = _context().scope
        state.raw_input.update({"tenant_id": "tenant-a", "run_id": "run-a"})
        gateway = InvestigationToolGateway(store, SQLiteActivityQueryAdapter(store), _boundary())
        process = gateway.invoke(
            "query_process_activities", {}, _context(), state.tool_ledger
        )
        # Only refs that appeared in this run's tool results may be explored.
        entity_ref = process.activities[0].subject_refs[0]
        entity = gateway.invoke(
            "explore_entity", {"entity_ref": entity_ref}, _context(), state.tool_ledger
        )
        candidate = entity.candidate_relations[0].relation_id
        verdict = CandidateVerdict(
            level="suspicious", threat_type="unknown", summary="存在待验证的可疑行为",
            supporting_refs=[process.evidence_references[0].evidence_id],
        )
        draft = ReportDraft(
            verdict=verdict, executive_summary="存在待验证的可疑行为",
            current_situation=[ReportStatement(
                statement_id="s1", text="可疑行为", supporting_refs=["unknown-ref"]
            )],
            query_boundary_refs=[process.query_id], asserted_host_refs=["host-2"],
            confirmed_relation_refs=[candidate],
        )
        issues = ReportGroundingValidator().validate(state, draft)
        codes = {issue.code for issue in issues}
        assert "unknown_evidence_ref" in codes
        assert "host_assertion_out_of_scope" in codes
        assert "relation_not_confirmed" in codes
        assert all(issue.blocking for issue in issues)
        locations = {issue.location for issue in issues}
        assert "current_situation[s1].supporting_refs" in locations
        assert "asserted_host_refs" in locations
        # The verdict itself cites valid run evidence and stays clean.
        assert "verdict.supporting_refs" not in locations
    finally:
        store.close()


class _QueueModel:
    """Serve different structured outputs for compose and each rejudge."""

    model_name = "fake-model"

    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls: list[dict] = []

    def with_structured_output(self, _schema, **_kwargs):
        outer = self

        class _Bound:
            def invoke(self, messages):
                outer.calls.append(messages)
                return outer.outputs.pop(0)

        return _Bound()


def test_repair_coordinator_rejudges_against_whitelist_and_may_change_conclusion(tmp_path: Path):
    store = _store(tmp_path)
    try:
        state = _state()
        state.scope = _context().scope
        state.raw_input.update({"tenant_id": "tenant-a", "run_id": "run-a"})
        gateway = InvestigationToolGateway(store, SQLiteActivityQueryAdapter(store), _boundary())
        process = gateway.invoke("query_process_activities", {}, _context(), state.tool_ledger)
        activity_ref = process.activities[0].activity_id
        broken = ReportDraft(
            verdict=CandidateVerdict(
                level="suspicious", threat_type="unknown",
                summary="引用了不存在证据的结论",
                supporting_refs=["invented-ref"],
            ),
            executive_summary="引用了不存在证据的结论",
            supporting_evidence_refs=["invented-ref"],
            query_boundary_refs=["invented-query"],
            asserted_host_refs=["outside-host"],
        )
        repaired = ReportDraft(
            verdict=CandidateVerdict(
                level="insufficient_evidence", threat_type="unknown",
                summary="原引用无效且无其他可引用证据，改为证据不足",
                supporting_refs=[],
            ),
            executive_summary="原引用无效且无其他可引用证据，结论为证据不足。",
            current_situation=[ReportStatement(
                statement_id="s1", text="本次运行仅返回一条进程活动",
                supporting_refs=[activity_ref],
            )],
            query_boundary_refs=[process.query_id],
            asserted_host_refs=["host-1"],
        )
        model = _QueueModel([repaired])
        composer = StructuredReportComposer(model)
        coordinator = ReportRepairCoordinator(composer)
        outcome = coordinator.evaluate(state, broken, max_rejudgments=2)
        assert outcome.issues == []
        assert outcome.rejudgments_used == 1
        assert not outcome.exhausted
        assert outcome.draft.verdict.level.value == "insufficient_evidence"
        # The rejudge prompt may only carry whitelisted evidence and IDs.
        import json as _json
        rejudge_instruction = _json.loads(model.calls[-1][-1]["content"])
        citable = rejudge_instruction["authorized_evidence"]["citable_activity_ids"]
        assert "invented-ref" not in citable
        assert activity_ref in citable
    finally:
        store.close()
