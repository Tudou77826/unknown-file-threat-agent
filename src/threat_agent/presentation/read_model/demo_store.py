from __future__ import annotations

from typing import Mapping, Protocol

from ...contracts import DemoComparisonReadModel


class DemoComparisonStore(Protocol):
    def get(self, dataset_id: str) -> DemoComparisonReadModel | None: ...

    def dataset_ids(self) -> list[str]: ...


class InMemoryDemoComparisonStore:
    def __init__(self, items: Mapping[str, DemoComparisonReadModel] | None = None):
        self._items = {
            key: value.model_copy(deep=True) for key, value in (items or {}).items()
        }

    def put(self, item: DemoComparisonReadModel) -> None:
        self._items[item.dataset_id] = item.model_copy(deep=True)

    def get(self, dataset_id: str) -> DemoComparisonReadModel | None:
        item = self._items.get(dataset_id)
        return item.model_copy(deep=True) if item is not None else None

    def dataset_ids(self) -> list[str]:
        return list(self._items)
