from fastapi.testclient import TestClient

from threat_agent.bootstrap.demo import build_all_comparisons
from threat_agent.bootstrap.settings import AppSettings
from threat_agent.presentation import InMemoryCaseReadStore, InMemoryDemoComparisonStore
from threat_agent.presentation.api.routes import create_app


class FakeRunService:
    def start(self, dataset_id, profile_id):
        assert dataset_id == "c2-benign-reference"
        assert profile_id == "l3-attribution-and-assets"
        return "ai-test"

    def get_investigation(self, run_id):
        if run_id != "ai-test":
            return None

        class Payload:
            @staticmethod
            def model_dump(mode="json"):
                return {
                    "run": {
                        "run_id": "ai-test",
                        "status": "running",
                        "stage": "investigating",
                    },
                    "reference_dataset_id": "c2-benign-reference",
                    "profile_id": "l3-attribution-and-assets",
                    "events": [],
                    "investigation_report": None,
                    "response_plan": None,
                }

        return Payload()


def test_full_demo_shows_data_readiness_by_profile(tmp_path):
    settings = AppSettings.load(
        environ={
            "THREAT_AGENT_MODE": "deterministic",
            "DEMO_DATA_STORE_PATH": str(tmp_path / "reference.sqlite"),
            "DEMO_DATASET_VERSION": "2026.08.1",
        },
        env_file=tmp_path / "missing.env",
    )
    comparisons = build_all_comparisons(settings)
    malicious = comparisons["c2-malicious-reference"]
    assert [len(item.readiness.answerable_questions) for item in malicious.profiles] == [0, 2, 4, 5]
    # Readiness is derived from profile visibility; no verdict is computed.
    assert all(item.case.judgment is None for item in malicious.profiles)
    assert malicious.fixed_conditions["rag_adapter"] == "null"

    assert set(comparisons) == {"c2-malicious-reference", "c2-benign-reference"}
    assert [
        profile.profile_id for profile in comparisons["c2-benign-reference"].profiles
    ] == ["l0-alert-only", "l1-process-context", "l2-behavior-telemetry", "l3-attribution-and-assets"]


def test_demo_page_can_start_and_observe_ai_run(tmp_path):
    settings = AppSettings.load(
        environ={
            "THREAT_AGENT_MODE": "deterministic",
            "DEMO_DATA_STORE_PATH": str(tmp_path / "reference.sqlite"),
            "DEMO_DATASET_VERSION": "2026.08.1",
        },
        env_file=tmp_path / "missing.env",
    )
    comparisons = build_all_comparisons(settings)
    client = TestClient(create_app(
        InMemoryCaseReadStore(), InMemoryDemoComparisonStore(comparisons), FakeRunService()
    ))
    formal_started = client.post(
        "/api/investigations",
        json={
            "reference_dataset_id": "c2-benign-reference",
            "profile_id": "l3-attribution-and-assets",
        },
    )
    assert formal_started.status_code == 202
    assert formal_started.json()["location"] == "/api/runs/ai-test"
    formal_observed = client.get("/api/runs/ai-test")
    assert formal_observed.status_code == 200
    assert formal_observed.json()["run"]["stage"] == "investigating"
    # The demo playbook has been retired; the legacy route must stay gone.
    assert client.get("/demo/c2-benign-reference").status_code == 404
