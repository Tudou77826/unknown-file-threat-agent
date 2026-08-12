from __future__ import annotations

from typing import Protocol

from ...contracts import EvidenceBundle, EvidenceQuery


class DataAccessError(ValueError):
    """Raised when a query violates its explicit data-access context."""


class EvidenceQueryPort(Protocol):
    def query_evidence(self, query: EvidenceQuery) -> EvidenceBundle: ...
