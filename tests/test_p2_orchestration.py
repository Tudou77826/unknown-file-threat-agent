import json
from pathlib import Path

from threat_agent.cli import run_case
from threat_agent.ingestion import initialize_state
from threat_agent.models import Coverage, EvidenceStatus
from threat_agent.orchestration import apply_pending_repair, plan_verdict_repairs
from threat_agent.planner import state_view
from threat_agent.repository import JsonlEventRepository
from threat_agent.tools import ToolRegistry


ROOT = Path(__file__).resolve().parents[1]


def setup_case(name):
    case_dir = ROOT / "cases" / name
    state = initialize_state(json.loads((case_dir / "input.json").read_text(encoding="utf-8")))
    return state, ToolRegistry(JsonlEventRepository(case_dir))


def test_catalog_exposes_auditable_score_components_and_counter_value():
    state, registry = setup_case("c2_benign")
    catalog = registry.catalog(state)
    execution = next(item for item in catalog if item["tool_name"] == "query_process_execution")
    counter = next(item for item in catalog if item["tool_name"] == "query_package_provenance")
    assert execution["score_breakdown"]["components"]["gap_priority"] > 0
    assert counter["score_breakdown"]["components"]["counter_evidence_value"] > 0
    assert catalog == sorted(catalog, key=lambda item: (-item["priority_score"], item["tool_name"]))


def test_unavailable_coverage_reduces_expected_tool_score():
    state, registry = setup_case("ransomware_malicious")
    original = next(item for item in registry.catalog(state) if item["tool_name"] == "query_bulk_file_modification")
    state.coverage["file"] = Coverage(domain="file", status=EvidenceStatus.UNAVAILABLE, completeness="unavailable")
    degraded = next(item for item in registry.catalog(state) if item["tool_name"] == "query_bulk_file_modification")
    assert degraded["priority_score"] < original["priority_score"]
    assert degraded["score_breakdown"]["components"]["coverage_expectation"] < 0


def test_every_successful_evidence_query_produces_an_evidence_pack():
    state = run_case(ROOT / "cases" / "exfil_https_malicious")
    evidence_calls = [call for call in state.tool_calls if call.action_type == "evidence_request" and call.status not in {"denied", "error"}]
    assert len(state.evidence_packs) == len(evidence_calls)
    evidence_ids = {item.evidence_id for item in state.evidence}
    obligation_ids = {item.obligation_id for item in state.analysis_obligations}
    for pack in state.evidence_packs:
        assert set(pack.evidence_refs) <= evidence_ids
        assert set(pack.analysis_obligation_refs) <= obligation_ids
        assert pack.coverage.domain


def test_verdict_failure_can_generate_and_apply_a_bounded_repair():
    state = run_case(ROOT / "cases" / "exfil_https_malicious")
    state.tool_calls = [item for item in state.tool_calls if item.tool_name != "query_data_transfer_baseline"]
    repairs = plan_verdict_repairs(state, ["Confirmed exfiltration requires transfer baseline evidence"])
    assert repairs
    assert repairs[0].target_gap_id == "gap-transfer-counter"
    applied = apply_pending_repair(state)
    assert applied.status == "applied"
    gap = next(item for item in state.evidence_gaps if item.gap_id == "gap-transfer-counter")
    assert gap.status == "open"
    assert state.budget.repair_actions_used == 1


def test_model_state_is_sliced_and_catalog_is_bounded():
    state, registry = setup_case("ransomware_malicious")
    payload = json.loads(state_view(state, registry))
    assert len(payload["available_tool_catalog"]) <= 12
    assert "recent_tool_calls" in payload
    assert "tool_calls" not in payload
    assert "pending_repair_actions" in payload


def test_reports_record_scores_packs_and_repairs_without_changing_verdict():
    state = run_case(ROOT / "cases" / "cross_host_scope_denied")
    assert state.tool_scores
    assert state.evidence_packs
    assert any(item.repair_type == "respect_scope_denial" and item.status == "applied" for item in state.repair_actions)
    assert state.verdict.level.value == "insufficient_evidence"
