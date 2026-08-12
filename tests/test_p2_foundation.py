import json
from pathlib import Path

from threat_agent.bootstrap.cli import run_case
from threat_agent.case_management import initialize_state
from threat_agent.judgment.application.planner import DeepAgentsPlanner
from threat_agent.case_management.application.reporting import evaluation_payload, report_payload, write_reports
from threat_agent.data_foundation.adapters.repository import JsonlEventRepository
from threat_agent.judgment.application.state import apply_evidence_bundle
from threat_agent.judgment.adapters.tools import ToolRegistry


ROOT = Path(__file__).resolve().parents[1]


def setup_case(name: str):
    case_dir = ROOT / "cases" / name
    raw = json.loads((case_dir / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    registry = ToolRegistry(JsonlEventRepository(case_dir))
    return state, registry


def test_analyzer_only_consumes_authorized_evidence_refs():
    state, registry = setup_case("c2_malicious")
    bundle = registry.invoke("query_process_network", state, {})
    apply_evidence_bundle(state, bundle, registry, {"network_connection"})
    selected = [item.evidence_id for item in bundle.evidence[:3]]

    result = registry.invoke("analyze_network", state, {"evidence_refs": selected})

    assert result.facts
    assert set(result.facts[0].evidence_refs) == set(selected)
    assert not any(item.finding_type == "periodic_external_connection" for item in result.findings)


def test_negative_analysis_outcome_is_preserved_for_benign_remote_command_gap():
    state = run_case(ROOT / "cases" / "c2_benign", "deterministic")
    gap = next(item for item in state.evidence_gaps if item.gap_id == "gap-remote-command")
    obligation = next(item for item in state.analysis_obligations if item.tool_name == "analyze_remote_command")

    assert obligation.outcome == "negative"
    assert gap.status == "resolved"
    assert gap.resolution == "negative"
    assert any("No inbound-command-outbound" in item for item in gap.limitations)


def test_deep_planner_records_structured_semantic_decision():
    state, registry = setup_case("c2_malicious")
    planner = DeepAgentsPlanner.__new__(DeepAgentsPlanner)
    planner.registry = registry
    planner._generate = lambda _instruction: {
        "tool_name": "query_process_execution",
        "target_hypothesis_id": "hyp-c2-001",
        "target_evidence_role_id": "role-execution",
        "target_gap_id": "gap-execution",
        "decision_summary": "Independent execution evidence is required before runtime behavior attribution.",
    }

    action = planner.plan(state)

    assert action.tool_name == "query_process_execution"
    decision = state.planner_decisions[-1]
    assert decision.target_hypothesis_id == "hyp-c2-001"
    assert decision.target_evidence_role_id == "role-execution"
    assert decision.target_gap_id == "gap-execution"
    assert decision.repaired is False


def test_report_and_evaluation_expose_validation_and_analysis_notes(tmp_path):
    state = run_case(ROOT / "cases" / "c2_benign", "deterministic")
    payload = report_payload(state)
    evaluation = evaluation_payload(state)

    assert payload["verdict_validation"] == {"status": "PASS", "errors": []}
    assert any("No inbound-command-outbound" in item for item in payload["analysis_notes"])
    assert evaluation["result"] == "PASS"
    assert evaluation["unsupported_path_edges"] == []

    json_path, md_path, evaluation_path = write_reports(state, tmp_path)
    assert json_path.exists() and md_path.exists() and evaluation_path.exists()


def test_case_expectations_are_machine_checkable():
    for case_name in ("c2_malicious", "c2_benign", "insufficient_evidence"):
        state = run_case(ROOT / "cases" / case_name, "deterministic")
        expected = json.loads((ROOT / "cases" / case_name / "expected.json").read_text(encoding="utf-8"))
        evaluation = evaluation_payload(state, expected)

        assert evaluation["verdict_match"] is True
        assert evaluation["threat_type_match"] is True
        assert evaluation["missing_required_findings"] == []
        assert evaluation["result"] == "PASS"
