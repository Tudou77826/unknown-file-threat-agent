import json
from pathlib import Path

from threat_agent.contracts import KnowledgeQuery
from threat_agent.case_management import initialize_state
from threat_agent.judgment import JudgmentGraph
from threat_agent.knowledge import NullKnowledgeRetriever
from threat_agent.judgment.domain.models import Finding
from threat_agent.judgment.application.planner import DeterministicPlanner
from threat_agent.data_foundation.adapters.repository import JsonlEventRepository
from threat_agent.judgment.adapters.tools import ToolRegistry
from threat_agent.judgment.domain.verdict import evaluate_verdict, validate_verdict


ROOT = Path(__file__).resolve().parents[1]
CASE_DIR = ROOT / "cases" / "c2_benign"


def test_null_retriever_reports_not_configured_without_fake_citations():
    result = NullKnowledgeRetriever().retrieve(
        KnowledgeQuery(
            tenant_id="tenant-a",
            case_id="case-a",
            source_identity="test-suite",
            query_id="knowledge-a",
            knowledge_domain="investigation",
            query_text="How should this case be investigated?",
        )
    )
    assert result.status == "not_configured"
    assert result.citations == []
    assert result.limitations


def test_judgment_graph_completes_when_rag_is_not_configured():
    raw = json.loads((CASE_DIR / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    registry = ToolRegistry(JsonlEventRepository(CASE_DIR))
    result = JudgmentGraph(
        registry,
        DeterministicPlanner(),
        knowledge_retriever=NullKnowledgeRetriever(),
    ).run(state)
    assert result.finished is True
    assert result.verdict is not None


def test_knowledge_id_cannot_be_used_as_verdict_evidence():
    raw = json.loads((CASE_DIR / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    state.findings.append(
        Finding(
            finding_id="finding-invalid-knowledge-ref",
            finding_type="invalid_reference_test",
            statement="Knowledge text must not be treated as case evidence",
            evidence_refs=["knowledge:document:chunk"],
            analyzer="test-suite",
            confidence=0.5,
        )
    )
    state.verdict = evaluate_verdict(state)
    errors = validate_verdict(state, state.verdict)
    assert any("unknown evidence" in error.lower() for error in errors)
