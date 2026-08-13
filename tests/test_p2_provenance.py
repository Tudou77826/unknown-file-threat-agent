import json
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage

from threat_agent.bootstrap.cli import run_case
from threat_agent.case_management import initialize_state
from threat_agent.judgment.application.planner import StructuredJudgmentPlanner
from threat_agent.judgment.domain.models import ScenarioActivationRequest
from threat_agent.case_management.application.reporting import evaluation_payload
from threat_agent.data_foundation.adapters.repository import JsonlEventRepository
from threat_agent.judgment.domain.scenarios import activate_scenario
from threat_agent.judgment.adapters.tools import ToolRegistry


ROOT = Path(__file__).resolve().parents[1]


class _ActivationModel:
    model_name = "fake-native-model"

    def __init__(self, tool_calls):
        self.tool_calls = tool_calls

    def bind_tools(self, tools, **_kwargs):
        self.bound_tools = tools
        return self

    def invoke(self, _messages):
        return AIMessage(content="", tool_calls=self.tool_calls)


ROOT = Path(__file__).resolve().parents[1]


def setup_case(name: str):
    case_dir = ROOT / "cases" / name
    raw = json.loads((case_dir / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    return state, ToolRegistry(JsonlEventRepository(case_dir))


def test_remote_command_analyzer_only_resolves_its_primary_gap():
    state = run_case(ROOT / "cases" / "c2_benign", "deterministic")
    obligation = next(item for item in state.analysis_obligations if item.tool_name == "analyze_remote_command")
    gaps = {item.gap_id: item for item in state.evidence_gaps}

    assert obligation.gap_ids == ["gap-remote-command"]
    assert obligation.primary_gap_id == "gap-remote-command"
    assert gaps["gap-remote-command"].resolution == "negative"
    assert gaps["gap-process-chain"].limitations == []
    assert gaps["gap-network"].limitations == []


def test_file_origin_tools_are_investigation_level_and_not_broad_loaders():
    state, registry = setup_case("provenance_download")
    names = {item.name for item in registry.list()}
    assert {
        "query_file_origin",
        "query_file_downloads",
        "query_file_transfer",
        "query_archive_extraction",
        "query_package_installation",
        "query_web_upload_activity",
        "analyze_file_provenance",
    } <= names
    catalog = {item["tool_name"] for item in registry.catalog(state)}
    assert "query_file_origin" in catalog


def test_download_provenance_builds_evidence_grounded_origin_path():
    state = run_case(ROOT / "cases" / "provenance_download", "deterministic")
    fact_types = {item.fact_type for item in state.facts}
    origin_relations = [item for item in state.relations if item.relation_id.startswith("rel-origin-")]
    evidence_ids = {item.evidence_id for item in state.evidence}

    assert {"file_downloaded", "file_created"} <= fact_types
    assert {item.relation_type for item in origin_relations} == {"delivered", "created"}
    assert all(set(item.evidence_refs) <= evidence_ids for item in origin_relations)
    gap = next(item for item in state.evidence_gaps if item.gap_id == "gap-file-origin")
    assert gap.resolution == "positive"
    hypothesis = next(item for item in state.hypotheses if item.hypothesis_type == "file_provenance")
    assert hypothesis.status == "supported"
    assert hypothesis.supporting_refs


def test_signed_package_provenance_is_a_deterministic_finding():
    state = run_case(ROOT / "cases" / "provenance_package", "deterministic")
    assert "file_installed_by_package" in {item.fact_type for item in state.facts}
    assert "trusted_package_installation" in {item.finding_type for item in state.findings}
    assert any(item.relation_type == "installed" for item in state.relations)


def test_unavailable_file_telemetry_keeps_provenance_unproven():
    state = run_case(ROOT / "cases" / "provenance_insufficient", "deterministic")
    gap = next(item for item in state.evidence_gaps if item.gap_id == "gap-file-origin")
    assert gap.status == "unresolvable"
    assert gap.resolution == "unresolvable"
    assert "file audit was not enabled" in gap.limitations
    assert not any(item.fact_type.startswith("file_") for item in state.facts)


def test_llm_scenario_activation_uses_reviewed_local_template():
    raw = json.loads((ROOT / "cases" / "c2_malicious" / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    registry = ToolRegistry(JsonlEventRepository(ROOT / "cases" / "c2_malicious"))
    planner = StructuredJudgmentPlanner(_ActivationModel([{
        "name": "activate_scenario",
        "args": {"scenario": "file_provenance", "reason_refs": ["ev-input-file-001"]},
        "id": "call-act-1",
        "type": "tool_call",
    }]), registry)

    action = planner.plan(state)

    assert isinstance(action, ScenarioActivationRequest)
    assert action.scenario == "file_provenance"
    assert state.planner_decisions[-1].activated_scenarios == ["file_provenance"]
    # The graph's activate_scenario node deterministically loads the template.
    activate_scenario(state, "file_provenance", ["ev-input-file-001"])
    assert "file_provenance" in state.active_scenarios
    assert any(item.hypothesis_id == "hyp-file-provenance-001" for item in state.hypotheses)
    assert any(item.role_id == "role-file-provenance" for item in state.evidence_roles)
    assert any(item.gap_id == "gap-file-origin" for item in state.evidence_gaps)
    assert "query_file_origin" in {item["tool_name"] for item in registry.catalog(state)}


def test_unknown_or_unsupported_scenario_activation_is_rejected():
    raw = json.loads((ROOT / "cases" / "c2_malicious" / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    with pytest.raises(ValueError, match="Unknown scenario activation"):
        activate_scenario(state, "invented_attack", ["ev-input-file-001"])
    with pytest.raises(ValueError, match="missing"):
        activate_scenario(state, "file_provenance", ["invented-evidence"])


def test_provenance_case_expectations_are_machine_checkable():
    for case_name in ("provenance_download", "provenance_package", "provenance_insufficient"):
        state = run_case(ROOT / "cases" / case_name, "deterministic")
        expected = json.loads((ROOT / "cases" / case_name / "expected.json").read_text(encoding="utf-8"))
        assert evaluation_payload(state, expected)["result"] == "PASS"
