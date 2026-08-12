from __future__ import annotations

from typing import Protocol

from ...contracts import KnowledgeQuery, KnowledgeResult


class KnowledgeRetrievalPort(Protocol):
    def retrieve(self, query: KnowledgeQuery) -> KnowledgeResult: ...
