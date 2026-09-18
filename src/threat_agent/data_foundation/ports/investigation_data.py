"""Aggregate read port used by the investigation tool gateway.

The judgment capability deliberately depends on this port instead of an
individual storage implementation. A provider adapter may combine a query
engine, an entity graph and raw-event storage behind the same investigation
access boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from ...contracts import EntityIdentity, NormalizedActivity, ObservedRelation
from .activity_query import (
    AssetActivityQueryPort,
    ExtensionActivityQueryPort,
    FileActivityQueryPort,
    NetworkActivityQueryPort,
    PackageActivityQueryPort,
    ProcessActivityQueryPort,
    ServiceActivityQueryPort,
    SocketActivityQueryPort,
)


@dataclass(frozen=True)
class EntityTimelineQuery:
    """Storage-neutral request for an entity's authorized activity timeline."""

    tenant_id: str
    entity_refs: set[str]
    host_refs: set[str]
    start_time: datetime | None
    end_time: datetime | None
    cursor: str | None
    limit: int


@dataclass(frozen=True)
class EntityTimelinePage:
    """A stable timeline page whose cursor semantics belong to the adapter."""

    activities: list[NormalizedActivity]
    next_cursor: str | None


@dataclass(frozen=True)
class ActivityRawRecord:
    """A visible normalized activity with its managed raw-event payload."""

    activity: NormalizedActivity
    payload: dict[str, Any]


class InvestigationDataPort(
    ProcessActivityQueryPort,
    NetworkActivityQueryPort,
    SocketActivityQueryPort,
    FileActivityQueryPort,
    ServiceActivityQueryPort,
    PackageActivityQueryPort,
    AssetActivityQueryPort,
    ExtensionActivityQueryPort,
    Protocol,
):
    """All data reads needed by a single investigation run.

    Implementations own provider-specific source visibility, entity alias
    resolution, relation traversal and raw-event access. The caller receives
    typed normalized records only and does not need SQLite, EDR or SIEM APIs.
    """

    def resolve_entity(self, tenant_id: str, entity_ref: str) -> EntityIdentity | None: ...

    def find_relations(
        self, tenant_id: str, entity_id: str, direction: str = "both"
    ) -> list[ObservedRelation]: ...

    def list_entity_timeline(self, query: EntityTimelineQuery) -> EntityTimelinePage: ...

    def get_raw_record(
        self, tenant_id: str, activity_ref: str
    ) -> ActivityRawRecord | None: ...

    def get_activities(
        self, tenant_id: str, activity_refs: list[str]
    ) -> list[NormalizedActivity | None]: ...
