from __future__ import annotations


class DataAccessError(ValueError):
    """Raised when a query violates its explicit data-access context."""
