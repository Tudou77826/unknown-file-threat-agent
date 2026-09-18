from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from threat_agent.contracts import (
    EvidenceQuery,
    InitialCase,
    KnowledgeConsultation,
    KnowledgeConsultationContext,
    KnowledgeItem,
)
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
    # 业务知识咨询只有业务语义字段；授权与证据体系都不出现在请求上
    knowledge_consultation = KnowledgeConsultation(
        scene="unknown_file_investigation",
        intent="telemetry_interpretation",
        context=KnowledgeConsultationContext(
            telemetry_field_ids=["netflow.session_reset_count"]
        ),
    )
    assert evidence_query.domain == "process"
    assert set(knowledge_consultation.model_dump()) == {"scene", "intent", "context"}
    # 知识条目不是证据：字段集合与证据契约无交集语义
    assert "evidence_id" not in KnowledgeItem.model_json_schema()["properties"]
    assert "evidence_refs" not in KnowledgeItem.model_json_schema()["properties"]


def test_contract_rejects_unknown_schema_major_version():
    with pytest.raises(ValidationError):
        InitialCase(
            **contract_fields(),
            schema_version="2.0",
            raw_input={},
            scope=Scope(host_ids=["host-a"]),
        )
