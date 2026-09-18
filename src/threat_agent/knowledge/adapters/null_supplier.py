from __future__ import annotations

from typing import Any

from ..ports.supplier_retrieval import (
    SupplierRetrievalRequest,
    SupplierSourceOutcome,
)

_NOT_CONFIGURED = "Knowledge retrieval is not configured for this deployment"


class NullKnowledgeSupplier:
    """未配置部署下的默认供应方适配器：每个请求的来源都返回 not_configured。"""

    supplier_id = "null-rag"

    def retrieve_sources(
        self, request: SupplierRetrievalRequest
    ) -> list[SupplierSourceOutcome]:
        return [
            SupplierSourceOutcome(
                source_category=query.source_category,
                status="not_configured",
                limitations=[_NOT_CONFIGURED],
                diagnostics={"supplier_id": self.supplier_id},
            )
            for query in request.sources
        ]

    def catalog(self) -> dict[str, Any] | None:
        return None
