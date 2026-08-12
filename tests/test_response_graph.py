import json
from pathlib import Path

from threat_agent.case_management import CaseGraph
from threat_agent.case_management import create_memory_checkpointer
from threat_agent.case_management.application.contract_builders import build_judgment_result
from threat_agent.case_management import initialize_state
from threat_agent.judgment import JudgmentGraph
from threat_agent.knowledge import NullKnowledgeRetriever
from threat_agent.judgment.application.planner import DeterministicPlanner
from threat_agent.data_foundation.adapters.repository import JsonlEventRepository
from threat_agent.response_advisory import DeterministicResponsePlanner, ResponseGraph
from threat_agent.response_advisory.domain.models import ResponseProposal
from threat_agent.judgment.adapters.tools import ToolRegistry


ROOT = Path(__file__).resolve().parents[1]


def completed_judgment(case_name: str):
    case_dir = ROOT / "cases" / case_name
    raw = json.loads((case_dir / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    registry = ToolRegistry(JsonlEventRepository(case_dir))
    completed = JudgmentGraph(registry, DeterministicPlanner()).run(state)
    return completed, build_judgment_result(completed, tenant_id="tenant-a")


def test_response_graph_generates_policy_valid_plan_without_rag():
    _state, judgment = completed_judgment("c2_malicious")
    plan = ResponseGraph(
        DeterministicResponsePlanner(),
        knowledge_retriever=NullKnowledgeRetriever(),
    ).run(judgment)
    assert plan.status == "approval_required"
    assert plan.actions
    assert all(action.preconditions for action in plan.actions)
    assert all(action.verification_steps for action in plan.actions)
    assert any("not configured" in item for item in plan.missing_context)
    assert judgment.verdict == build_judgment_result(_state, tenant_id="tenant-a").verdict


class InvalidPlanner:
    def __init__(self):
        self.calls = 0

    def propose(self, judgment, knowledge, validation_errors, response_context=None):
        self.calls += 1
        return ResponseProposal(actions=[])


def test_response_graph_honors_independent_repair_budget():
    _state, judgment = completed_judgment("c2_malicious")
    planner = InvalidPlanner()
    plan = ResponseGraph(planner, max_iterations=2).run(judgment)
    assert planner.calls == 2
    assert plan.status == "insufficient_context"
    assert plan.actions == []


def test_parent_graph_runs_second_loop_and_interrupts_for_response_approval():
    case_dir = ROOT / "cases" / "c2_malicious"
    raw = json.loads((case_dir / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    registry = ToolRegistry(JsonlEventRepository(case_dir))
    judgment_graph = JudgmentGraph(registry, DeterministicPlanner(), scope_approval_mode="defer")
    response_graph = ResponseGraph(DeterministicResponsePlanner())
    parent = CaseGraph(
        judgment_graph,
        checkpointer=create_memory_checkpointer(),
        response_graph=response_graph,
    )
    paused = parent.start(state, tenant_id="tenant-a", run_id="dual-loop")
    assert paused["lifecycle_status"] == "awaiting_response_approval"
    assert paused["response_plan"].status == "approval_required"
    assert paused["__interrupt__"]
    completed = parent.resume_response(
        tenant_id="tenant-a",
        case_id=state.case_id,
        run_id="dual-loop",
        approved=True,
        approved_by="security-lead",
    )
    assert completed["lifecycle_status"] == "advised"
    assert completed["approval_status"] == "response_approved_by:security-lead"
