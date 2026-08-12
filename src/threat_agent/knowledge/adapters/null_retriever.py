from __future__ import annotations

from ...contracts import KnowledgeQuery, KnowledgeResult


class NullKnowledgeRetriever:
    """Explicitly report that RAG is outside the current implementation scope."""

    def retrieve(self, query: KnowledgeQuery) -> KnowledgeResult:
        return KnowledgeResult(
            tenant_id=query.tenant_id,
            case_id=query.case_id,
            source_identity="knowledge:null-adapter",
            query_id=query.query_id,
            status="not_configured",
            citations=[],
            limitations=["Knowledge retrieval is not configured for this deployment"],
        )
