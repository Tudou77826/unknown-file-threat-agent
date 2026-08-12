from pathlib import Path

from threat_agent.bootstrap.cli import run_case
from threat_agent.judgment.domain.models import VerdictLevel


ROOT = Path(__file__).resolve().parents[1]


def run(name: str):
    return run_case(ROOT / "cases" / name)


def test_https_exfiltration_requires_one_ordered_object_linked_chain():
    state = run("exfil_https_malicious")
    assert state.verdict.level == VerdictLevel.CONFIRMED_MALICIOUS
    assert state.verdict.threat_type == "data_exfiltration"
    assert "confirmed_data_exfiltration" in {item.finding_type for item in state.findings}
    assert "exfiltrated_to" in {item.relation_type for item in state.relations}
    assert not state.verdict_validation_errors


def test_dns_exfiltration_requires_process_attributed_payload_pattern():
    state = run("exfil_dns_malicious")
    types = {item.finding_type for item in state.findings}
    assert state.verdict.level == VerdictLevel.CONFIRMED_MALICIOUS
    assert {"dns_tunnel_pattern", "confirmed_data_exfiltration"} <= types
    assert "exfiltrated_via" in {item.relation_type for item in state.relations}
    assert not state.verdict_validation_errors


def test_approved_backup_is_counter_evidence_not_false_positive():
    state = run("exfil_benign_backup")
    types = {item.finding_type for item in state.findings}
    assert state.verdict.level in {VerdictLevel.BENIGN, VerdictLevel.LIKELY_BENIGN}
    assert "legitimate_backup_explanation" in types
    assert "confirmed_data_exfiltration" not in types
    assert not state.verdict_validation_errors


def test_unavailable_sensitive_and_egress_telemetry_stays_insufficient():
    state = run("exfil_insufficient")
    assert state.verdict.level == VerdictLevel.INSUFFICIENT_EVIDENCE
    assert state.coverage["file"].status.value == "unavailable"
    assert state.coverage["network"].status.value == "unavailable"
    assert not state.verdict_validation_errors


def test_every_exfiltration_path_edge_resolves_to_evidence():
    for case_name in ("exfil_https_malicious", "exfil_dns_malicious", "exfil_benign_backup"):
        state = run(case_name)
        evidence_ids = {item.evidence_id for item in state.evidence}
        entity_ids = {item.entity_id for item in state.entities}
        for relation in state.relations:
            assert set(relation.evidence_refs) <= evidence_ids
            assert {relation.source_entity_ref, relation.target_entity_ref} <= entity_ids
