"""Stable case projections and read-only presentation adapters."""

from .projection.case_projector import case_read_payload
from .read_model.store import InMemoryCaseReadStore
from .read_model.demo_store import InMemoryDemoComparisonStore

__all__ = ["InMemoryCaseReadStore", "InMemoryDemoComparisonStore", "case_read_payload"]
