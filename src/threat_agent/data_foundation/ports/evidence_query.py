from __future__ import annotations


class DataAccessError(ValueError):
    """Raised when a query violates its explicit data-access context."""


class UnsupportedDataQuery(DataAccessError):
    """The configured source does not provide this read capability."""


class DataQueryFailed(DataAccessError):
    """A supported source query failed; this is not a successful empty result."""
