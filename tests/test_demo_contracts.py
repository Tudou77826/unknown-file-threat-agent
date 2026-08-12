from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from threat_agent.contracts import (
    DataProfile,
    DataReadinessReport,
    ReadinessQuestion,
    SourceCoverageRule,
)


def profile_payload() -> dict:
    return {
        "profile_id": "c2-malicious-l1",
        "dataset_version": "1.0",
        "level": "l1",
        "visible_sources": ["alert", "edr-process"],
        "coverage_rules": [
            {
                "source_id": "edr-process",
                "domains": ["process"],
                "status": "available",
                "completeness": "complete",
            }
        ],
        "asset_context_visible": False,
        "description": "Execution-level telemetry",
    }


def test_data_profile_round_trip_has_no_expected_verdict():
    profile = DataProfile.model_validate(profile_payload())
    restored = DataProfile.model_validate_json(profile.model_dump_json())
    assert restored == profile
    assert "verdict" not in restored.model_dump_json().lower()


def test_profile_rejects_duplicate_sources_and_unknown_schema():
    duplicate = profile_payload()
    duplicate["visible_sources"] = ["alert", "alert"]
    with pytest.raises(ValidationError, match="visible_sources"):
        DataProfile.model_validate(duplicate)
    unsupported = profile_payload()
    unsupported["schema_version"] = "2.0"
    with pytest.raises(ValidationError):
        DataProfile.model_validate(unsupported)


def test_readiness_report_round_trip():
    report = DataReadinessReport(
        tenant_id="default",
        case_id="case-1",
        created_at=datetime.now(timezone.utc),
        run_id="run-1",
        profile_id="l0",
        dataset_version="1.0",
        missing_sources=["edr-process"],
        blocked_questions=[
            ReadinessQuestion(
                question_id="execution",
                question="Was the file executed?",
                evidence_role_ids=["role-execution"],
                required_domains=["process"],
                required_sources=["edr-process"],
                status="blocked",
            )
        ],
    )
    assert DataReadinessReport.model_validate_json(report.model_dump_json()) == report


def test_source_rule_requires_domains():
    with pytest.raises(ValidationError):
        SourceCoverageRule(
            source_id="edr-process",
            domains=[],
            status="available",
            completeness="complete",
        )
