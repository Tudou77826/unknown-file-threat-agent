import json
from pathlib import Path

import pytest

from threat_agent.case_management import initialize_state
from threat_agent.judgment.domain.models import AnalysisRequest, EvidenceRequest, FinishRequest
from threat_agent.judgment.application.planner import DeepAgentsPlanner
from threat_agent.judgment.application.policy import PolicyError, validate_action
from threat_agent.data_foundation.adapters.repository import JsonlEventRepository
from threat_agent.judgment.application.state import apply_evidence_bundle
from threat_agent.judgment.adapters.tools import ToolRegistry


ROOT = Path(__file__).resolve().parents[1]
CASE_DIR = ROOT / "cases" / "c2_malicious"


def setup_case():
    raw = json.loads((CASE_DIR / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    registry = ToolRegistry(JsonlEventRepository(CASE_DIR))
    return state, registry


def finish_action(state):
    return FinishRequest(
        objective="Attempt closure after accounting for every evidence gap",
        resolved_gap_ids=[gap.gap_id for gap in state.evidence_gaps if gap.status == "resolved"],
        unresolved_gap_ids=[gap.gap_id for gap in state.evidence_gaps if gap.status != "resolved"],
    )


def test_evidence_collection_creates_required_analysis_obligations():
    state, registry = setup_case()
    bundle = registry.invoke("query_process_execution", state, {})
    apply_evidence_bundle(state, bundle, registry)

    assert next(gap for gap in state.evidence_gaps if gap.gap_id == "gap-execution").status == "evidence_collected"
    obligations = {item.tool_name: item for item in state.analysis_obligations}
    assert obligations["analyze_execution"].status == "pending"
    assert "analyze_process_chain" not in obligations


def test_finish_gate_rejects_collected_but_unanalyzed_evidence():
    state, registry = setup_case()
    bundle = registry.invoke("query_process_execution", state, {})
    apply_evidence_bundle(state, bundle, registry)

    with pytest.raises(PolicyError, match="required analysis obligations remain"):
        validate_action(finish_action(state), state, registry)


def test_finish_gate_rejects_unattempted_mandatory_gaps():
    state, registry = setup_case()
    with pytest.raises(PolicyError, match="mandatory evidence gaps were not attempted"):
        validate_action(finish_action(state), state, registry)


def test_deep_planner_prioritizes_required_analysis_without_model_call():
    state, registry = setup_case()
    bundle = registry.invoke("query_process_execution", state, {})
    apply_evidence_bundle(state, bundle, registry)

    planner = DeepAgentsPlanner.__new__(DeepAgentsPlanner)
    planner.registry = registry
    action = planner.plan(state)

    assert isinstance(action, AnalysisRequest)
    assert action.tool_name == "analyze_execution"
    assert action.evidence_refs == ["raw-proc-exec-target"]


class FailingStructuredModel:
    def __init__(self):
        self.calls = 0

    def invoke(self, *_args, **_kwargs):
        self.calls += 1
        raise ValueError("empty structured response")


def test_deep_planner_retries_empty_responses_then_uses_catalog_fallback():
    state, registry = setup_case()
    planner = DeepAgentsPlanner.__new__(DeepAgentsPlanner)
    planner.registry = registry
    planner.system_prompt = "test prompt"
    planner.structured_model = FailingStructuredModel()

    action = planner.plan(state)

    assert planner.structured_model.calls == 3
    assert isinstance(action, EvidenceRequest)
    assert action.tool_name == registry.catalog(state)[0]["tool_name"]
