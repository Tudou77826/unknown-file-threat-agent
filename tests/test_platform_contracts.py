from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from threat_agent.contracts import EvidenceQuery, InitialCase, KnowledgeQuery, KnowledgeResult
from threat_agent.judgment.domain.models import Scope


def contract_fields():
    return {
        "tenant_id": "tenant-test",
        "case_id": "case-test",
        "created_at": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "source_identity": "test-suite",
    }


def test_initial_case_contract_round_trip():
    contract = InitialCase(
        **contract_fields(),
        raw_input={"File_hash": "abc"},
        scope=Scope(host_ids=["host-a"]),
    )
    restored = InitialCase.model_validate_json(contract.model_dump_json())
    assert restored == contract
    assert restored.schema_version == "1.0"


def test_evidence_and_knowledge_contracts_are_distinct():
    evidence_query = EvidenceQuery(
        **contract_fields(),
        query_id="query-evidence",
        domain="process",
        evidence_types=["process_exec"],
        scope=Scope(host_ids=["host-a"]),
    )
    knowledge_query = KnowledgeQuery(
        **contract_fields(),
        query_id="query-knowledge",
        knowledge_domain="investigation",
        query_text="How should process execution be verified?",
    )
    result = KnowledgeResult(
        **contract_fields(),
        query_id=knowledge_query.query_id,
        status="not_configured",
        limitations=["Knowledge retrieval is not configured"],
    )
    assert evidence_query.domain == "process"
    assert result.citations == []


def test_contract_rejects_unknown_schema_major_version():
    with pytest.raises(ValidationError):
        InitialCase(
            **contract_fields(),
            schema_version="2.0",
            raw_input={},
            scope=Scope(host_ids=["host-a"]),
        )
