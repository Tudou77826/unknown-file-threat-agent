"""Supplier-shaped retrieval port — the adapter layer's internal dependency.

The capability layer turns a business consultation into per-source query text
plus management-plane options; only here does that plan meet a concrete
supplier. Adapters own protocol, routing, authentication, timeouts, error
normalization and item standardization. Raw supplier scores and other
diagnostics travel in ``diagnostics`` and never enter business contracts.
"""

from __future__ import annotations

from typing import Any, Literal, Protocol

from pydantic import Field

from ...contracts import KnowledgeRelevance, KnowledgeSourceCategory
from ...shared import StrictModel


class SupplierSourceQuery(StrictModel):
    """能力层生成的面向供应方的单源查询：查询文本是中间产物，不进入业务契约。"""

    source_category: KnowledgeSourceCategory
    query_text: str = Field(min_length=1)
    options: dict[str, Any] = Field(default_factory=dict)


class SupplierRetrievalRequest(StrictModel):
    query_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    actor_id: str = Field(min_length=1)
    timeout_seconds: float = Field(gt=0)
    sources: list[SupplierSourceQuery] = Field(min_length=1)


class SupplierItem(StrictModel):
    """适配层标准化后的供应方条目：归一相关性等级由各适配器按自身量纲给出。"""

    knowledge_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    chunk_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    content: str = Field(min_length=1)
    source_uri: str = Field(min_length=1)
    relevance: KnowledgeRelevance
    item_limitations: list[str] = Field(default_factory=list)
    supplier_metadata: dict[str, Any] = Field(default_factory=dict)


SupplierOutcomeStatus = Literal[
    "available", "empty", "not_configured", "permission_denied", "timeout", "error"
]


class SupplierSourceOutcome(StrictModel):
    """单源访问结果：失败按源隔离，错误归一为可区分状态。"""

    source_category: KnowledgeSourceCategory
    status: SupplierOutcomeStatus
    items: list[SupplierItem] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    diagnostics: dict[str, Any] = Field(default_factory=dict)


class SupplierRetrievalPort(Protocol):
    def retrieve_sources(
        self, request: SupplierRetrievalRequest
    ) -> list[SupplierSourceOutcome]: ...

    def catalog(self) -> dict[str, Any] | None:
        """Operator-facing corpus description (never model-visible); None when
        the supplier exposes no catalog."""
        ...
