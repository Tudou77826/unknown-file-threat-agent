from pathlib import Path

from threat_agent.cli import run_case
from threat_agent.models import VerdictLevel

ROOT = Path(__file__).resolve().parents[1]


def run(name):
    return run_case(ROOT / "cases" / name)


def test_complete_ransomware_chain_is_confirmed_and_grounded():
    state = run("ransomware_malicious")
    assert state.verdict.level == VerdictLevel.CONFIRMED_MALICIOUS
    assert state.verdict.threat_type == "ransomware"
    assert {"broad_high_rate_file_impact", "probable_file_encryption", "recovery_inhibition", "confirmed_ransomware_impact"} <= {f.finding_type for f in state.findings}
    assert not state.verdict_validation_errors


def test_failed_destructive_attempt_is_not_actual_recovery_destruction():
    state = run("ransomware_partial_attempt")
    assert state.verdict.level == VerdictLevel.SUSPICIOUS
    assert "recovery_inhibition" not in {f.finding_type for f in state.findings}


def test_authorized_batch_transformation_is_benign_counterexample():
    state = run("ransomware_benign_batch")
    assert state.verdict.level in {VerdictLevel.BENIGN, VerdictLevel.LIKELY_BENIGN}
    assert "legitimate_batch_explanation" in {f.finding_type for f in state.findings}
    assert "confirmed_ransomware_impact" not in {f.finding_type for f in state.findings}


def test_missing_file_and_recovery_sources_remain_insufficient():
    state = run("ransomware_insufficient")
    assert state.verdict.level == VerdictLevel.INSUFFICIENT_EVIDENCE
    assert state.coverage["file"].status.value == "unavailable"
    assert state.coverage["persistence"].status.value == "unavailable"
