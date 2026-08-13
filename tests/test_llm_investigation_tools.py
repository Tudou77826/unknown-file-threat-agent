from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage

from threat_agent.case_management import initialize_state
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
    DataAccessError,
    ReferenceEventParser,
    SQLiteActivityQueryAdapter,
    SQLiteActivityStore,
)
from threat_agent.judgment import InvestigationToolGateway
from threat_agent.judgment.application.data_tool_planner import DataToolSelection, StructuredDataToolPlanner
from threat_agent.judgment.application.reporting import DeterministicReportComposer, ReportDraft, StructuredReportComposer
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


def test_gateway_exposes_only_four_data_tools_and_routes_typed_query(tmp_path: Path):
    store = _store(tmp_path)
    try:
        emitted = []
        gateway = InvestigationToolGateway(
            store,
            SQLiteActivityQueryAdapter(store),
            event_sink=lambda kind, message, details=None: emitted.append(
                (kind, message, details)
            ),
        )
        ledger = InvestigationToolLedger()
        assert gateway.tool_names == (
            "query_activities", "explore_entity", "get_raw_records", "calculate_activity_metrics"
        )
        result = gateway.invoke(
            "query_activities",
            {"activity_type": "process", "filters": {"operations": ["execute"]}},
            _context(), ledger,
        )
        assert result.execution_boundary.returned_count == 1
        assert ledger.authorized_activity_refs == [result.activities[0].activity_id]
        assert result.interface_definition.interface_id == "activity-query/process"
        assert emitted[0][0] == "tool"
        assert emitted[0][2]["tool_name"] == "query_activities"
        assert emitted[0][2]["returned_count"] == 1
        assert emitted[0][2]["duration_ms"] >= 0
    finally:
        store.close()


def test_gateway_rejects_cross_domain_filters_and_scope_expansion(tmp_path: Path):
    store = _store(tmp_path)
    try:
        gateway = InvestigationToolGateway(store, SQLiteActivityQueryAdapter(store))
        with pytest.raises(DataAccessError):
            gateway.invoke(
                "query_activities",
                {"activity_type": "process", "filters": {"protocols": ["tcp"]}},
                _context(), InvestigationToolLedger(),
            )
        with pytest.raises(DataAccessError):
            gateway.invoke(
                "query_activities", {"activity_type": "process", "host_refs": ["host-2"]},
                _context(), InvestigationToolLedger(),
            )
    finally:
        store.close()


def test_raw_and_metric_tools_require_activity_returned_in_same_run(tmp_path: Path):
    store = _store(tmp_path)
    try:
        gateway = InvestigationToolGateway(store, SQLiteActivityQueryAdapter(store))
        ledger = InvestigationToolLedger()
        with pytest.raises(DataAccessError):
            gateway.invoke(
                "get_raw_records", {"activity_refs": ["activity-process-1"]}, _context(), ledger
            )
        query = gateway.invoke(
            "query_activities", {"activity_type": "network"}, _context(), ledger
        )
        ref = query.activities[0].activity_id
        raw = gateway.invoke("get_raw_records", {"activity_refs": [ref]}, _context(), ledger)
        assert raw.records[0].payload["event_type"] == "network_connection"
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


def test_data_tool_planner_can_only_select_four_tools_or_two_actions():
    state = _state()
    model = _FakeModel({AIMessage: AIMessage(content="", tool_calls=[{
        "name": "query_activities",
        "args": {"activity_type": "process", "entity_refs": ["process:host-1:10:1"]},
        "id": "call-native-1",
        "type": "tool_call",
    }])})
    planner = StructuredDataToolPlanner(model)
    action = planner.plan(state)
    assert isinstance(action, DataToolRequest)
    assert action.tool_name == "query_activities"
    assert action.arguments["entity_refs"] == ["process:host-1:10:1"]
    assert action.tool_call_id == "call-native-1"
    schemas = {tool.name: tool.args_schema.model_json_schema() for tool in model.bound_tools}
    assert "entity_refs" in schemas["query_activities"]["properties"]
    assert "entity_id" not in schemas["query_activities"]["properties"]


def test_data_tool_planner_stops_repeated_tool_loop_before_model_call():
    state = _state()
    state.budget.iterations_used = 4
    for index in range(3):
        state.tool_calls.append(ToolCall(
            call_id=f"call-{index}", tool_name="get_raw_records",
            action_type="data_tool_request", status="success",
            objective="读取已查询活动对应的原始记录并核验关键字段",
        ))
    planner = StructuredDataToolPlanner(_FakeModel({}))
    action = planner.plan(state)
    assert isinstance(action, FinishRequest)
    assert "没有增加新的数据能力" in action.objective


def test_data_tool_planner_has_hard_online_iteration_cap():
    state = _state()
    state.budget.max_iterations = 48
    state.budget.iterations_used = 12
    planner = StructuredDataToolPlanner(_FakeModel({}))
    action = planner.plan(state)
    assert isinstance(action, FinishRequest)
    assert "轮次上限" in action.objective


def test_report_validator_rejects_unknown_refs_scope_and_candidate_relations(tmp_path: Path):
    store = _store(tmp_path)
    try:
        state = _state()
        state.scope = _context().scope
        state.raw_input.update({"tenant_id": "tenant-a", "run_id": "run-a"})
        gateway = InvestigationToolGateway(store, SQLiteActivityQueryAdapter(store))
        process = gateway.invoke(
            "query_activities", {"activity_type": "process"}, _context(), state.tool_ledger
        )
        entity_id = next(
            item.entity_id for item in store.list_entities("tenant-a") if item.entity_type == "process"
        )
        entity = gateway.invoke(
            "explore_entity", {"entity_ref": entity_id}, _context(), state.tool_ledger
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
        composer = StructuredReportComposer(_FakeModel({ReportDraft: draft}))
        report = composer.compose(state)
        errors = composer.validate(state, report)
        assert any("未知对象" in item for item in errors)
        assert any("超出授权 Scope" in item for item in errors)
        assert any("候选关系" in item for item in errors)
    finally:
        store.close()


def test_offline_report_composer_publishes_chinese_contract():
    state = _state()
    state.verdict = CandidateVerdict(
        level="insufficient_evidence", threat_type="unknown", summary="当前证据不足以完成定性"
    )
    report = DeterministicReportComposer().compose(state)
    assert report.executive_summary == "当前证据不足以完成定性"
    assert DeterministicReportComposer().validate(state, report) == []


def test_structured_report_repair_sanitizes_references_without_calling_model():
    state = _state()
    draft = ReportDraft(
        verdict=CandidateVerdict(
            level="suspicious",
            threat_type="unknown",
            summary="存在需要继续调查的活动",
            supporting_refs=["invented-ref"],
        ),
        executive_summary="存在需要继续调查的活动",
        supporting_evidence_refs=["invented-ref"],
        query_boundary_refs=["invented-query"],
        asserted_host_refs=["outside-host"],
    )
    composer = StructuredReportComposer(_FakeModel({ReportDraft: draft}))
    report = composer.compose(state)
    repaired = composer.repair(state, report, composer.validate(state, report))
    assert repaired.report_version == 2
    assert repaired.verdict.supporting_refs == []
    assert repaired.supporting_evidence_refs == []
    assert repaired.query_boundary_refs == []
    assert repaired.asserted_host_refs == []
    assert composer.validate(state, repaired) == []
