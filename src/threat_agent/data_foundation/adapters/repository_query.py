from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ...contracts import EvidenceBundle, EvidenceQuery, Scope
from .repository import EvidenceRepository
from ..ports.evidence_query import DataAccessError


@dataclass(frozen=True)
class _ScopeCarrier:
    """Compatibility object for the legacy repository during migration."""

    scope: Scope


def _as_datetime(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


class RepositoryEvidenceQueryAdapter:
    """Expose a legacy case repository through the data-foundation port."""

    def __init__(self, repository: EvidenceRepository):
        self.repository = repository

    def query_evidence(self, query: EvidenceQuery) -> EvidenceBundle:
        if query.domain not in query.scope.allowed_domains:
            raise DataAccessError(f"Domain {query.domain!r} is outside the authorized scope")
        parameters = dict(query.parameters)
        requested_host = parameters.get("host_id")
        if requested_host and str(requested_host) not in query.scope.host_ids:
            raise DataAccessError(f"Host {requested_host!r} is outside the authorized scope")
        requested_start = _as_datetime(parameters.get("start_time"))
        requested_end = _as_datetime(parameters.get("end_time"))
        if requested_start and query.scope.start_time and requested_start < query.scope.start_time:
            raise DataAccessError("Requested start_time is outside the authorized scope")
        if requested_end and query.scope.end_time and requested_end > query.scope.end_time:
            raise DataAccessError("Requested end_time is outside the authorized scope")
        parameters["limit"] = min(int(parameters.get("limit", query.limit)), query.limit)
        return self.repository.query(
            query.domain,
            frozenset(query.evidence_types),
            _ScopeCarrier(query.scope),  # type: ignore[arg-type]
            parameters,
        )
