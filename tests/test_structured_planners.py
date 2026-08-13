import json
from pathlib import Path

from langchain_core.messages import AIMessage, ToolMessage

from threat_agent.case_management.application.contract_builders import build_judgment_result
from threat_agent.case_management import initialize_state
from threat_agent.judgment import JudgmentGraph
from threat_agent.judgment.domain.models import (
    AnalysisRequest,
    EvidenceRequest,
    FinishRequest,
    ScenarioActivationRequest,
    ToolCall,
)
from threat_agent.judgment.application.planner import DeterministicPlanner, StructuredJudgmentPlanner
from threat_agent.judgment.application.state import apply_evidence_bundle
from threat_agent.data_foundation.adapters.repository import JsonlEventRepository
from threat_agent.response_advisory.domain.models import ResponseProposal
from threat_agent.response_advisory.application.planner import StructuredResponsePlanner
from threat_agent.judgment.adapters.tools import ToolRegistry


ROOT = Path(__file__).resolve().parents[1]


class BoundStructuredModel:
    def __init__(self, schema):
        self.schema = schema

    def invoke(self, _messages):
        if self.schema is ResponseProposal:
            return ResponseProposal(actions=[])
        raise AssertionError(f"Unexpected schema: {self.schema}")


class BoundToolModel:
    def __init__(self, tool_calls):
        self.tool_calls = tool_calls

    def invoke(self, _messages):
        return AIMessage(content="", tool_calls=self.tool_calls)


class FakeChatModel:
    model_name = "fake-native-model"

    def with_structured_output(self, schema, **_kwargs):
        return BoundStructuredModel(schema)

    def bind_tools(self, tools, **_kwargs):
        self.bound_tools = tools
        return BoundToolModel(self._tool_calls)

    def __init__(self):
        self._tool_calls = []


def setup_case(case_name="c2_malicious"):
    case_dir = ROOT / "cases" / case_name
    raw = json.loads((case_dir / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    return state, ToolRegistry(JsonlEventRepository(case_dir))


def _planner(state, registry, tool_calls):
    model = FakeChatModel()
    model._tool_calls = tool_calls
    return StructuredJudgmentPlanner(model, registry)


def test_judgment_planner_uses_native_tool_calling_for_domain_query():
    state, registry = setup_case()
    planner = _planner(
        state, registry,
        [{"name": "query_process_evidence", "args": {"gap_id": "gap-execution"}, "id": "call-1", "type": "tool_call"}],
    )
    action = planner.plan(state)
    assert isinstance(action, EvidenceRequest)
    assert action.tool_name == "query_process_evidence"
    assert action.gap_id == "gap-execution"
    assert action.parameters == {}


def test_judgment_planner_maps_analysis_to_pending_obligation():
    state, registry = setup_case()
    # Seed evidence so an analysis obligation becomes pending.
    bundle = registry.invoke("query_process_execution", state, {})
    from threat_agent.judgment.application.state import apply_evidence_bundle
    apply_evidence_bundle(state, bundle, registry)
    pending = next(item for item in state.analysis_obligations if item.status == "pending")
    planner = _planner(
        state, registry,
        [{"name": "analyze_evidence", "args": {"evidence_refs": pending.evidence_refs}, "id": "call-2", "type": "tool_call"}],
    )
    action = planner.plan(state)
    assert isinstance(action, AnalysisRequest)
    assert action.tool_name == pending.tool_name
    assert set(action.evidence_refs) == set(pending.evidence_refs)


def test_judgment_planner_maps_scenario_activation():
    state, registry = setup_case()
    planner = _planner(
        state, registry,
        [{"name": "activate_scenario", "args": {"scenario": "file_provenance", "reason_refs": ["ev-input-file-001"]}, "id": "call-3", "type": "tool_call"}],
    )
    action = planner.plan(state)
    assert isinstance(action, ScenarioActivationRequest)
    assert action.scenario == "file_provenance"
    assert action.reason_refs == ["ev-input-file-001"]


def test_response_planner_binds_response_proposal_schema():
    state, registry = setup_case("c2_benign")
    completed = JudgmentGraph(registry, DeterministicPlanner()).run(state)
    judgment = build_judgment_result(completed)
    proposal = StructuredResponsePlanner(FakeChatModel()).propose(judgment, [], [], None)
    assert isinstance(proposal, ResponseProposal)


def test_finish_investigation_uses_deterministic_gap_accounting():
    state, registry = setup_case()
    planner = _planner(
        state, registry,
        [{"name": "finish_investigation", "args": {
            "objective": "现有证据已足以形成结论，结束调查并生成报告。",
            "resolved_gap_ids": ["gap-does-not-exist"],
            "unresolved_gap_ids": [],
        }, "id": "call-f", "type": "tool_call"}],
    )
    action = planner.plan(state)
    assert isinstance(action, FinishRequest)
    # Model-supplied gap lists are ignored; accounting is deterministic.
    known = {gap.gap_id for gap in state.evidence_gaps}
    assert set(action.resolved_gap_ids) | set(action.unresolved_gap_ids) == known
    assert "gap-does-not-exist" not in action.resolved_gap_ids


def test_replay_maps_analyzer_back_to_analyze_evidence_with_results():
    state, registry = setup_case()
    bundle = registry.invoke("query_process_execution", state, {})
    apply_evidence_bundle(state, bundle, registry)
    obligation = next(item for item in state.analysis_obligations if item.status == "pending")
    obligation.status = "completed"
    obligation.outcome = "positive"
    obligation.result_refs = ["fact-exec-001"]
    state.tool_calls.append(ToolCall(
        call_id="call-analysis-1",
        tool_name=obligation.tool_name,  # concrete analyzer, e.g. analyze_execution
        action_type="analysis_request",
        status="success",
        objective="运行确定性分析",
        parameters={"evidence_refs": list(obligation.evidence_refs)},
    ))
    planner = _planner(state, registry, [])
    replay = planner._replay(state)
    ai_names = [m.tool_calls[0]["name"] for m in replay if isinstance(m, AIMessage)]
    assert "analyze_evidence" in ai_names
    tool_payloads = [json.loads(m.content) for m in replay if isinstance(m, ToolMessage)]
    assert any("fact-exec-001" in json.dumps(p, ensure_ascii=False) for p in tool_payloads)
