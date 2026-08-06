from pathlib import Path

from threat_agent.cli import run_case
from threat_agent.models import VerdictLevel


ROOT = Path(__file__).resolve().parents[1]


def run(name: str):
    return run_case(ROOT / "cases" / name)


def test_malicious_case_is_confirmed_with_required_proof():
    state = run("c2_malicious")
    assert state.verdict.level == VerdictLevel.CONFIRMED_MALICIOUS
    assert state.verdict.threat_type == "backdoor_c2"
    assert "file_executed" in {x.fact_type for x in state.facts}
    assert "remote_command_execution" in {x.finding_type for x in state.findings}
    assert "active_persistence" in {x.finding_type for x in state.findings}


def test_benign_case_is_not_misclassified_by_periodic_connection_and_persistence():
    state = run("c2_benign")
    assert state.verdict.level in {VerdictLevel.BENIGN, VerdictLevel.LIKELY_BENIGN}
    assert "legitimate_software_explanation" in {x.finding_type for x in state.findings}


def test_insufficient_case_reports_data_source_limitations():
    state = run("insufficient_evidence")
    assert state.verdict.level == VerdictLevel.INSUFFICIENT_EVIDENCE
    assert state.coverage["network"].status.value == "unavailable"
    assert state.coverage["persistence"].status.value == "unavailable"


def test_all_output_references_resolve():
    state = run("c2_malicious")
    evidence_ids = {x.evidence_id for x in state.evidence}
    for fact in state.facts:
        assert set(fact.evidence_refs) <= evidence_ids
    for finding in state.findings:
        assert set(finding.evidence_refs) <= evidence_ids
    for relation in state.relations:
        assert set(relation.evidence_refs) <= evidence_ids

