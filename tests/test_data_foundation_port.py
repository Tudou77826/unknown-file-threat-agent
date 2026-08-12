import json
from pathlib import Path

import pytest

from threat_agent.contracts import EvidenceQuery
from threat_agent.data_foundation import DataAccessError, RepositoryEvidenceQueryAdapter
from threat_agent.case_management import initialize_state
from threat_agent.data_foundation.adapters.repository import JsonlEventRepository


ROOT = Path(__file__).resolve().parents[1]
CASE_DIR = ROOT / "cases" / "c2_malicious"


def setup_query():
    raw = json.loads((CASE_DIR / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    repository = JsonlEventRepository(CASE_DIR)
    query = EvidenceQuery(
        tenant_id="default",
        case_id=state.case_id,
        source_identity="test-suite",
        query_id="query-process-execution",
        domain="process",
        evidence_types=["process_exec"],
        scope=state.scope,
    )
    return state, repository, query


def test_repository_adapter_preserves_evidence_and_coverage_semantics():
    state, repository, query = setup_query()
    legacy = repository.query("process", frozenset({"process_exec"}), state, {})
    adapted = RepositoryEvidenceQueryAdapter(repository).query_evidence(query)
    assert [item.evidence_id for item in adapted.evidence] == [item.evidence_id for item in legacy.evidence]
    assert adapted.coverage == legacy.coverage


def test_repository_adapter_rejects_host_outside_scope():
    _state, repository, query = setup_query()
    invalid = query.model_copy(update={"parameters": {"host_id": "host-not-authorized"}})
    with pytest.raises(DataAccessError, match="outside the authorized scope"):
        RepositoryEvidenceQueryAdapter(repository).query_evidence(invalid)


def test_empty_result_retains_complete_coverage():
    _state, repository, query = setup_query()
    missing = query.model_copy(update={"evidence_types": ["not_present"]})
    result = RepositoryEvidenceQueryAdapter(repository).query_evidence(missing)
    assert result.evidence == []
    assert result.coverage.completeness == "complete"
