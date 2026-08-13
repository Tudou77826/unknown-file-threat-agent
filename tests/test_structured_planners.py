import json
from pathlib import Path

from threat_agent.case_management.application.contract_builders import build_judgment_result
from threat_agent.case_management import initialize_state
from threat_agent.judgment import JudgmentGraph
from threat_agent.judgment.domain.models import EvidenceRequest
from threat_agent.judgment.application.planner import DeterministicPlanner, PlannerSelection, StructuredJudgmentPlanner
from threat_agent.data_foundation.adapters.repository import JsonlEventRepository
from threat_agent.response_advisory.domain.models import ResponseProposal
from threat_agent.response_advisory.application.planner import StructuredResponsePlanner
from threat_agent.judgment.adapters.tools import ToolRegistry


ROOT = Path(__file__).resolve().parents[1]


class BoundStructuredModel:
    def __init__(self, schema):
        self.schema = schema

    def invoke(self, _messages):
        if self.schema is PlannerSelection:
            return PlannerSelection(
                tool_name="query_process_execution",
                target_gap_id="gap-execution",
                decision_summary="Collect independent process execution telemetry first",
            )
        if self.schema is ResponseProposal:
            return ResponseProposal(actions=[])
        raise AssertionError(f"Unexpected schema: {self.schema}")


class FakeChatModel:
    model_name = "fake-structured-model"

    def with_structured_output(self, schema, **_kwargs):
        return BoundStructuredModel(schema)


def setup_case(case_name="c2_malicious"):
    case_dir = ROOT / "cases" / case_name
    raw = json.loads((case_dir / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    return state, ToolRegistry(JsonlEventRepository(case_dir))


def test_judgment_planner_uses_model_native_structured_output():
    state, registry = setup_case()
    planner = StructuredJudgmentPlanner(FakeChatModel(), registry)
    action = planner.plan(state)
    assert isinstance(action, EvidenceRequest)
    assert action.tool_name == "query_process_execution"


def test_response_planner_binds_response_proposal_schema():
    state, registry = setup_case("c2_benign")
    completed = JudgmentGraph(registry, DeterministicPlanner()).run(state)
    judgment = build_judgment_result(completed)
    proposal = StructuredResponsePlanner(FakeChatModel()).propose(judgment, [], [], None)
    assert isinstance(proposal, ResponseProposal)
