"""SQLite implementation of the aggregate investigation data port."""

from __future__ import annotations

from ...contracts import EntityIdentity, NormalizedActivity, ObservedRelation
from ..ports.evidence_query import DataAccessError
from ..ports.investigation_data import (
    ActivityRawRecord,
    EntityTimelinePage,
    EntityTimelineQuery,
)
from .activity_query import SQLiteActivityQueryAdapter
from .activity_store import SQLiteActivityStore


class SQLiteInvestigationDataAdapter:
    """Compose SQLite query, entity and raw-record reads behind one port.

    visible_sources is applied consistently to domain queries, entity
    timelines, raw-record access and resolved relations. This closes the
    former bypass where only the domain-query adapter honored a data profile.
    """

    def __init__(
        self,
        store: SQLiteActivityStore,
        *,
        visible_sources: set[str] | None = None,
    ):
        self._store = store
        self._visible_sources = (
            frozenset(visible_sources) if visible_sources is not None else None
        )
        self._queries = SQLiteActivityQueryAdapter(
            store, visible_sources=visible_sources
        )

    # Typed domain-query ports -------------------------------------------------

    def query_process(self, query):
        return self._queries.query_process(query)

    def query_network(self, query):
        return self._queries.query_network(query)

    def query_socket(self, query):
        return self._queries.query_socket(query)

    def query_file(self, query):
        return self._queries.query_file(query)

    def query_service(self, query):
        return self._queries.query_service(query)

    def query_package(self, query):
        return self._queries.query_package(query)

    def query_asset(self, query):
        return self._queries.query_asset(query)

    def query_extension(self, query):
        return self._queries.query_extension(query)

    # Entity, timeline and raw-record access ----------------------------------

    def resolve_entity(self, tenant_id: str, entity_ref: str) -> EntityIdentity | None:
        identity = self._store.get_entity(tenant_id, entity_ref)
        if identity is not None:
            return identity
        for candidate in self._store.list_entities(tenant_id):
            if any(alias.source_id == entity_ref for alias in candidate.aliases):
                return candidate
        return None

    def find_relations(
        self, tenant_id: str, entity_id: str, direction: str = "both"
    ) -> list[ObservedRelation]:
        relations = self._store.find_relations(tenant_id, entity_id, direction)
        if self._visible_sources is None:
            return relations
        return [
            relation
            for relation in relations
            if not relation.supporting_activity_refs
            or any(
                self.get_activities(tenant_id, [activity_ref])[0] is not None
                for activity_ref in relation.supporting_activity_refs
            )
        ]

    def list_entity_timeline(self, query: EntityTimelineQuery) -> EntityTimelinePage:
        offset = self._decode_offset(query.cursor)
        timeline: list[NormalizedActivity] = []
        for activity in self._store.list_activities(query.tenant_id):
            if not self._is_visible(activity):
                continue
            refs = (
                set(activity.subject_refs)
                | set(activity.actor_refs)
                | set(activity.target_refs)
            )
            if not refs.intersection(query.entity_refs):
                continue
            activity_host = getattr(activity, "host_ref", None)
            if activity_host is not None and activity_host not in query.host_refs:
                continue
            if query.start_time is not None and activity.observed_at < query.start_time:
                continue
            if query.end_time is not None and activity.observed_at > query.end_time:
                continue
            timeline.append(activity)
        page = timeline[offset:offset + query.limit]
        next_cursor = (
            str(offset + query.limit)
            if offset + query.limit < len(timeline)
            else None
        )
        return EntityTimelinePage(activities=page, next_cursor=next_cursor)

    def get_raw_record(
        self, tenant_id: str, activity_ref: str
    ) -> ActivityRawRecord | None:
        activity = self.get_activities(tenant_id, [activity_ref])[0]
        if activity is None:
            return None
        payload = self._store.get_raw_payload(tenant_id, activity.raw_record_ref)
        if payload is None:
            return None
        return ActivityRawRecord(activity=activity, payload=payload)

    def get_activities(
        self, tenant_id: str, activity_refs: list[str]
    ) -> list[NormalizedActivity | None]:
        activities: list[NormalizedActivity | None] = []
        for activity_ref in activity_refs:
            activity = self._store.get_activity(tenant_id, activity_ref)
            activities.append(
                activity if activity is not None and self._is_visible(activity) else None
            )
        return activities

    def _is_visible(self, activity: NormalizedActivity) -> bool:
        return (
            self._visible_sources is None
            or activity.source_system in self._visible_sources
        )

    @staticmethod
    def _decode_offset(cursor: str | None) -> int:
        if cursor is None:
            return 0
        try:
            value = int(cursor)
        except ValueError as error:
            raise DataAccessError("Invalid entity timeline cursor") from error
        if value < 0:
            raise DataAccessError("Invalid entity timeline cursor")
        return value
