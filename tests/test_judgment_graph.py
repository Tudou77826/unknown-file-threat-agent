import json
from pathlib import Path

import pytest

from threat_agent.judgment.application.engine import InvestigationEngine
from threat_agent.case_management import initialize_state
from threat_agent.judgment import JudgmentGraph
from threat_agent.judgment.application.planner import DeterministicPlanner
from threat_agent.data_foundation.adapters.repository import JsonlEventRepository
from threat_agent.judgment.adapters.tools import ToolRegistry


ROOT = Path(__file__).resolve().parents[1]
CASE_NAMES = sorted(path.name for path in (ROOT / "cases").iterdir() if path.is_dir())


def run(case_name: str, graph: bool):
    case_dir = ROOT / "cases" / case_name
    raw = json.loads((case_dir / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    registry = ToolRegistry(JsonlEventRepository(case_dir))
    runner = JudgmentGraph(registry, DeterministicPlanner()) if graph else InvestigationEngine(
        registry, DeterministicPlanner()
    )
    return runner.run(state)


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_langgraph_judgment_matches_legacy_engine(case_name):
    legacy = run(case_name, graph=False)
    migrated = run(case_name, graph=True)
    assert migrated.finished is True
    assert migrated.verdict.level == legacy.verdict.level
    assert migrated.verdict.threat_type == legacy.verdict.threat_type
    assert {item.fact_type for item in migrated.facts} == {item.fact_type for item in legacy.facts}
    assert {item.finding_type for item in migrated.findings} == {
        item.finding_type for item in legacy.findings
    }
    assert {
        ref for item in migrated.findings for ref in item.evidence_refs
    } == {ref for item in legacy.findings for ref in item.evidence_refs}
    assert migrated.verdict_validation_errors == legacy.verdict_validation_errors


def test_graph_nodes_return_a_new_state_instance():
    case_dir = ROOT / "cases" / "c2_malicious"
    raw = json.loads((case_dir / "input.json").read_text(encoding="utf-8"))
    original = initialize_state(raw)
    registry = ToolRegistry(JsonlEventRepository(case_dir))
    result = JudgmentGraph(registry, DeterministicPlanner()).run(original)
    assert original.finished is False
    assert original.budget.iterations_used == 0
    assert result.finished is True
