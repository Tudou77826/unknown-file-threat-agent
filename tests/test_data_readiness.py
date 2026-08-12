import json
from pathlib import Path

from threat_agent.case_management.application import evaluate_data_readiness
from threat_agent.case_management.application.intake import initialize_state
from threat_agent.contracts import DataProfile


ROOT = Path(__file__).parents[1]


def test_answerable_questions_increase_monotonically_across_profiles():
    raw = json.loads((ROOT / "cases/c2_malicious/input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    counts = []
    for level in ["l0", "l1", "l2", "l3"]:
        profile = DataProfile.model_validate_json(
            (ROOT / f"demo_data/profiles/{level}.json").read_text(encoding="utf-8")
        )
        report = evaluate_data_readiness(
            state, profile, tenant_id="demo", run_id=f"run-{level}"
        )
        counts.append(len(report.answerable_questions))
        assert report.case_id == state.case_id
    assert counts == sorted(counts)
    assert counts == [0, 2, 4, 5]


def test_readiness_does_not_mutate_or_decide_verdict():
    raw = json.loads((ROOT / "cases/c2_malicious/input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    before = state.model_dump_json()
    profile = DataProfile.model_validate_json(
        (ROOT / "demo_data/profiles/l3.json").read_text(encoding="utf-8")
    )
    report = evaluate_data_readiness(state, profile, tenant_id="demo", run_id="run-l3")
    assert state.model_dump_json() == before
    assert state.verdict is None
    assert not hasattr(report, "verdict")
