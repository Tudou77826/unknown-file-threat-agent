from __future__ import annotations

from typing import Protocol

from ...contracts import CaseReadModel


class CaseReadStore(Protocol):
    def get(self, tenant_id: str, case_id: str) -> CaseReadModel | None: ...


class InMemoryCaseReadStore:
    def __init__(self):
        self._items: dict[tuple[str, str], CaseReadModel] = {}

    def put(self, item: CaseReadModel) -> None:
        self._items[(item.tenant_id, item.case_id)] = item.model_copy(deep=True)

    def get(self, tenant_id: str, case_id: str) -> CaseReadModel | None:
        item = self._items.get((tenant_id, case_id))
        return item.model_copy(deep=True) if item is not None else None
