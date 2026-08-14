import json
from pathlib import Path

from threat_agent.case_management.application import evaluate_data_readiness
from threat_agent.contracts import DataProfile


ROOT = Path(__file__).parents[1]


def test_answerable_questions_increase_monotonically_across_profiles():
    case_id = "case-a06b4392935d"
    counts = []
    for level in ["l0", "l1", "l2", "l3"]:
        profile = DataProfile.model_validate_json(
            (ROOT / f"demo_data/profiles/{level}.json").read_text(encoding="utf-8")
        )
        report = evaluate_data_readiness(
            profile, case_id=case_id, tenant_id="demo", run_id=f"run-{level}"
        )
        counts.append(len(report.answerable_questions))
        assert report.case_id == case_id
    assert counts == sorted(counts)
    assert counts[-1] > counts[0]


def test_readiness_does_not_decide_verdict():
    profile = DataProfile.model_validate_json(
        (ROOT / "demo_data/profiles/l3.json").read_text(encoding="utf-8")
    )
    report = evaluate_data_readiness(
        profile, case_id="case-a06b4392935d", tenant_id="demo", run_id="run-l3"
    )
    assert not hasattr(report, "verdict")
