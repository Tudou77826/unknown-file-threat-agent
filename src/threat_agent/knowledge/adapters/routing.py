"""Category-level supplier routing (Feature 18).

A generic composition over ``SupplierRetrievalPort``: each source category may
be owned by a dedicated supplier, everything else falls through to a default
supplier. Per-supplier failures are isolated — one supplier breaking degrades
only its own categories, mirroring the per-source isolation the capability
layer already guarantees. Catalogs merge by category name with routed
suppliers taking precedence over the default. The router knows nothing about
ATT&CK or any concrete corpus; it only knows the port.
"""

from __future__ import annotations

from typing import Any, Mapping

from ...contracts import KnowledgeSourceCategory
from ..ports.supplier_retrieval import (
    SupplierRetrievalPort,
    SupplierRetrievalRequest,
    SupplierSourceOutcome,
    SupplierSourceQuery,
)


class RoutingSupplier(SupplierRetrievalPort):
    def __init__(
        self,
        *,
        routes: Mapping[KnowledgeSourceCategory, SupplierRetrievalPort],
        default: SupplierRetrievalPort,
    ):
        self._routes = dict(routes)
        self._default = default
        suppliers = [default, *self._routes.values()]
        supplier_ids: list[str] = []
        for supplier in suppliers:
            supplier_id = getattr(supplier, "supplier_id", None) or supplier.__class__.__name__
            if supplier_id not in supplier_ids:
                supplier_ids.append(supplier_id)
        self.supplier_id = "routing[" + " + ".join(supplier_ids) + "]"

    def retrieve_sources(
        self, request: SupplierRetrievalRequest
    ) -> list[SupplierSourceOutcome]:
        # Group queries by owning supplier (stable, request order preserved),
        # call each supplier once with only its queries, then reassemble.
        grouped: dict[int, list[tuple[int, SupplierSourceQuery, SupplierRetrievalPort]]] = {}
        for position, query in enumerate(request.sources):
            supplier = self._routes.get(query.source_category, self._default)
            grouped.setdefault(id(supplier), []).append((position, query, supplier))

        outcomes: dict[int, SupplierSourceOutcome] = {}
        for entries in grouped.values():
            supplier = entries[0][2]
            sub_request = SupplierRetrievalRequest(
                query_id=request.query_id,
                tenant_id=request.tenant_id,
                case_id=request.case_id,
                actor_id=request.actor_id,
                timeout_seconds=request.timeout_seconds,
                sources=[query for _position, query, _supplier in entries],
            )
            try:
                results = supplier.retrieve_sources(sub_request)
                if len(results) != len(entries):
                    raise ValueError(
                        f"供应商 {supplier.supplier_id} 返回 {len(results)} 个来源结果，"
                        f"与请求的 {len(entries)} 个不一致"
                    )
            except Exception as error:  # noqa: BLE001 — 单一供应方故障按其类别隔离为 error
                results = [
                    SupplierSourceOutcome(
                        source_category=query.source_category,
                        status="error",
                        limitations=[f"供应商异常：{type(error).__name__}: {error}"],
                        diagnostics={"supplier_id": self.supplier_id},
                    )
                    for _position, query, _supplier in entries
                ]
            for (position, query, _supplier), outcome in zip(entries, results):
                if outcome.source_category != query.source_category:
                    outcome = outcome.model_copy(update={"source_category": query.source_category})
                outcomes[position] = outcome
        return [outcomes[position] for position in range(len(request.sources))]

    def catalog(self) -> dict[str, Any] | None:
        merged: dict[str, dict[str, Any]] = {}
        for supplier in (self._default, *self._routes.values()):
            try:
                catalog = supplier.catalog()
            except Exception:  # noqa: BLE001 — 目录是运营面信息，单方失败只少它一份
                continue
            if not catalog:
                continue
            for category in catalog.get("categories", []):
                name = category.get("category")
                if name:
                    merged[name] = category
        if not merged:
            return None
        return {"supplier_id": self.supplier_id, "categories": list(merged.values())}
