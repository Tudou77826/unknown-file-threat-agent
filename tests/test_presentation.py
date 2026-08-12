import json
from pathlib import Path

from fastapi.testclient import TestClient

from threat_agent.case_management import initialize_state
from threat_agent.judgment import JudgmentGraph
from threat_agent.judgment.application.planner import DeterministicPlanner
from threat_agent.case_management import build_case_read_model
from threat_agent.presentation import InMemoryCaseReadStore, case_read_payload
from threat_agent.presentation.api.routes import create_app
from threat_agent.data_foundation.adapters.repository import JsonlEventRepository
from threat_agent.judgment.adapters.tools import ToolRegistry


ROOT = Path(__file__).resolve().parents[1]


def read_model(case_name: str = "c2_malicious"):
    case_dir = ROOT / "cases" / case_name
    raw = json.loads((case_dir / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    registry = ToolRegistry(JsonlEventRepository(case_dir))
    completed = JudgmentGraph(registry, DeterministicPlanner()).run(state)
    return build_case_read_model(completed, tenant_id="tenant-a")


def test_case_read_model_contains_stable_judgment_and_timeline():
    model = read_model()
    payload = case_read_payload(model)
    assert payload["schema_version"] == "1.0"
    assert payload["verdict"]["level"] == "confirmed_malicious"
    assert payload["evidence"]
    assert payload["investigation_timeline"]


def test_read_only_api_uses_tenant_scoped_store():
    model = read_model()
    store = InMemoryCaseReadStore()
    store.put(model)
    client = TestClient(create_app(store))
    response = client.get(
        f"/api/cases/{model.case_id}", headers={"x-tenant-id": "tenant-a"}
    )
    assert response.status_code == 200
    assert response.json()["case_id"] == model.case_id
    assert client.get(f"/api/cases/{model.case_id}").status_code == 404


def test_case_page_escapes_untrusted_case_content():
    model = read_model("c2_benign")
    model.facts.append({
        "fact_id": "untrusted",
        "statement": "<script>alert('x')</script>",
        "evidence_refs": [],
    })
    store = InMemoryCaseReadStore()
    store.put(model)
    client = TestClient(create_app(store))
    response = client.get(
        f"/cases/{model.case_id}", headers={"x-tenant-id": "tenant-a"}
    )
    assert response.status_code == 200
    assert "<script>alert" not in response.text
    assert "&lt;script&gt;" in response.text
