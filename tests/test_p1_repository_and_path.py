import json
from pathlib import Path

from threat_agent.bootstrap.cli import run_case
from threat_agent.case_management import initialize_state
from threat_agent.judgment.domain.models import EvidenceRequest
from threat_agent.judgment.application.policy import PolicyError, validate_action
from threat_agent.data_foundation.adapters.repository import JsonlEventRepository
from threat_agent.case_management.application.reporting import report_payload
from threat_agent.judgment.adapters.tools import ToolRegistry
from threat_agent.judgment.domain.verdict import validate_verdict


ROOT = Path(__file__).resolve().parents[1]
CASE_DIR = ROOT / "cases" / "c2_malicious"


def setup_case():
    raw = json.loads((CASE_DIR / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    registry = ToolRegistry(JsonlEventRepository(CASE_DIR))
    return state, registry


def test_repository_filters_by_type_host_entity_time_fields_and_limit():
    state, registry = setup_case()
    file_ref = next(entity.entity_id for entity in state.entities if entity.entity_type == "file")
    execution = registry.invoke("query_process_execution", state, {"host_id": "server-01", "entity_ids": [file_ref]})
    assert [item.evidence_id for item in execution.evidence] == ["raw-proc-exec-target"]

    network = registry.invoke("query_process_network", state, {
        "start_time": "2026-04-23T03:22:00Z",
        "end_time": "2026-04-23T03:24:00Z",
        "filters": {"remote_ip": "203.0.113.50", "remote_port": 443},
        "limit": 2,
    })
    assert [item.evidence_id for item in network.evidence] == ["raw-net-002", "raw-net-003"]
    assert any("truncated" in item for item in network.limitations)


def test_policy_rejects_out_of_scope_query_parameters():
    state, registry = setup_case()
    action = EvidenceRequest(
        tool_name="query_process_execution",
        gap_id="gap-execution",
        objective="Query execution evidence on an unauthorized host",
        parameters={"host_id": "server-outside-scope"},
    )
    try:
        validate_action(action, state, registry)
    except PolicyError as exc:
        assert "outside the approved scope" in str(exc)
    else:
        raise AssertionError("Out-of-scope host was accepted")


def test_raw_events_do_not_contain_precomputed_attack_conclusions():
    forbidden = {"remote_command_observed", "activated", "trusted_package", "known_service_endpoint"}
    for path in (CASE_DIR / "events").glob("*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            assert not (forbidden & set(event.get("data", {})))


def test_attack_path_edges_have_real_evidence_and_existing_entities():
    state = run_case(CASE_DIR, "deterministic")
    evidence_ids = {item.evidence_id for item in state.evidence}
    entity_ids = {item.entity_id for item in state.entities}
    assert state.relations
    for relation in state.relations:
        assert relation.evidence_refs
        assert set(relation.evidence_refs) <= evidence_ids
        assert relation.source_entity_ref in entity_ids
        assert relation.target_entity_ref in entity_ids
    assert validate_verdict(state, state.verdict) == []


def test_remote_command_finding_is_derived_from_independent_raw_events():
    state = run_case(CASE_DIR, "deterministic")
    finding = next(item for item in state.findings if item.finding_type == "remote_command_execution")
    evidence_by_id = {item.evidence_id: item for item in state.evidence}
    types = {evidence_by_id[ref].evidence_type for ref in finding.evidence_refs}
    assert {"network_connection", "socket_io", "child_process_exec", "process_parent_relation"} <= types
    assert len([item for item in state.findings if item.finding_type == "remote_command_execution"]) == 1


def test_registry_exposes_investigation_tools_not_broad_domain_loaders():
    state, registry = setup_case()
    names = {item.name for item in registry.list()}
    assert {"query_process_execution", "query_process_relations", "query_child_process_execution", "query_process_network", "query_socket_activity", "query_systemd_events", "query_package_provenance", "query_approved_endpoints"} <= names
    assert not ({"query_process_events", "query_network_events", "query_persistence_events", "query_reputation_events"} & names)


def test_domain_coverage_merges_all_investigation_queries():
    state = run_case(CASE_DIR, "deterministic")
    process = state.coverage["process"]
    network = state.coverage["network"]
    assert process.completeness == "complete"
    assert network.completeness == "complete"
    assert process.available_start == state.scope.start_time
    assert process.available_end == state.scope.end_time
    assert process.result_start.isoformat() == "2026-04-23T03:17:13.979000+00:00"
    assert process.result_end.isoformat() == "2026-04-23T03:24:02+00:00"
    assert network.result_start.isoformat() == "2026-04-23T03:21:00+00:00"
    assert network.result_end.isoformat() == "2026-04-23T03:24:03+00:00"


def test_report_contains_resolvable_evidence_index_for_attack_path():
    state = run_case(CASE_DIR, "deterministic")
    payload = report_payload(state)
    indexed = {item["evidence_id"] for item in payload["evidence"]}
    assert payload["entities"]
    assert all(set(edge["evidence_refs"]) <= indexed for edge in payload["attack_path"])
