import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from threat_agent.engine import InvestigationEngine
from threat_agent.ingestion import initialize_state
from threat_agent.models import AnalysisRequest, EvidenceRequest, FinishRequest
from threat_agent.planner import ACTION_ADAPTER, DeterministicPlanner
from threat_agent.policy import PolicyError, validate_action
from threat_agent.repository import JsonlEventRepository
from threat_agent.tools import ToolRegistry


ROOT = Path(__file__).resolve().parents[1]
CASE_DIR = ROOT / "cases" / "c2_malicious"


def setup_case():
    raw = json.loads((CASE_DIR / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    registry = ToolRegistry(JsonlEventRepository(CASE_DIR))
    return state, registry


def test_action_schema_rejects_empty_objective_and_missing_tool_name():
    with pytest.raises(ValidationError):
        ACTION_ADAPTER.validate_python({
            "action_type": "evidence_request",
            "objective": "",
            "gap_id": "gap-execution",
        })


def test_policy_rejects_invented_evidence_reference():
    state, registry = setup_case()
    action = AnalysisRequest(
        tool_name="analyze_execution",
        objective="Verify execution using independent process telemetry",
        evidence_refs=["ev-does-not-exist"],
    )
    with pytest.raises(PolicyError, match="unknown evidence IDs"):
        validate_action(action, state, registry)


def test_catalog_only_exposes_analysis_tools_when_prerequisites_exist():
    state, registry = setup_case()
    initial_names = {item["tool_name"] for item in registry.catalog(state)}
    assert "query_process_execution" in initial_names
    assert "query_file_activity" not in initial_names
    assert "analyze_execution" not in initial_names

    bundle = registry.invoke("query_process_execution", state, {})
    from threat_agent.state import apply_evidence_bundle

    apply_evidence_bundle(state, bundle, registry)
    updated_names = {item["tool_name"] for item in registry.catalog(state)}
    assert "analyze_execution" in updated_names
    assert "query_process_relations" in updated_names


class RepairingPlanner:
    def __init__(self):
        self.plan_calls = 0
        self.repair_calls = 0

    def plan(self, state):
        self.plan_calls += 1
        if self.plan_calls == 1:
            return EvidenceRequest(
                tool_name="query_process_network",
                objective="Collect evidence for the execution evidence gap",
                gap_id="gap-execution",
            )
        return DeterministicPlanner().plan(state)

    def repair(self, state, invalid_action, validation_error):
        self.repair_calls += 1
        assert "cannot resolve gap-execution" in validation_error
        return EvidenceRequest(
            tool_name="query_process_execution",
            objective="Collect independent execution records for the unknown file",
            gap_id="gap-execution",
        )


def test_engine_allows_one_policy_repair_before_execution():
    state, registry = setup_case()
    planner = RepairingPlanner()
    result = InvestigationEngine(registry, planner).run(state)

    assert planner.repair_calls == 1
    assert all(call.status != "denied" for call in result.tool_calls)
    assert any(evidence.evidence_type == "process_exec" for evidence in result.evidence)
    assert all(item.status == "completed" for item in result.analysis_obligations)
    assert result.finished is True
