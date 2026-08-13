from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from ...contracts import (
    ActivityQueryBase,
    ActivityQueryResult,
    AssetActivityQuery,
    EvidenceReference,
    ExtensionActivityQuery,
    FileActivityQuery,
    NetworkActivityQuery,
    PackageActivityQuery,
    ProcessActivityQuery,
    QueryExecutionBoundary,
    QueryFieldDefinition,
    QueryInterfaceDefinition,
    QueryScopeSnapshot,
    ServiceActivityQuery,
    SocketActivityQuery,
)
from ..ports.evidence_query import DataAccessError
from .activity_store import SQLiteActivityStore, _ACTIVITY_ADAPTER


INTERFACE_VERSION = "1.0"


_SCOPE_DOMAIN_BY_ACTIVITY = {
    "process": "process", "network": "network", "socket": "network",
    "file": "file", "service": "persistence", "package": "reputation",
    "asset": "reputation", "extension": "extension",
}


def _cursor(observed_at: str, activity_id: str) -> str:
    raw = json.dumps([observed_at, activity_id], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(value: str) -> tuple[str, str]:
    try:
        padded = value + "=" * (-len(value) % 4)
        result = json.loads(base64.urlsafe_b64decode(padded).decode())
        if not isinstance(result, list) or len(result) != 2:
            raise ValueError
        return str(result[0]), str(result[1])
    except Exception as error:
        raise DataAccessError("Invalid activity query cursor") from error


def _source_event_type(activity) -> str | None:
    return activity.extension.get("source_event_type") or activity.extension.get("event_type")


def _all_refs(activity) -> set[str]:
    refs = set(activity.subject_refs) | set(activity.actor_refs) | set(activity.target_refs)
    for name in (
        "host_ref", "process_ref", "parent_process_ref", "source_endpoint_ref",
        "destination_endpoint_ref", "socket_ref", "file_ref", "acting_process_ref",
        "service_ref", "executable_ref", "package_ref", "asset_ref",
    ):
        value = getattr(activity, name, None)
        if value:
            refs.add(str(value))
    return refs


class SQLiteActivityQueryAdapter:
    """Translate typed activity queries to SQLite without exposing storage details upstream."""

    def __init__(self, store: SQLiteActivityStore, *, visible_sources: set[str] | None = None):
        self.store = store
        self.visible_sources = visible_sources

    def query_process(self, query: ProcessActivityQuery) -> ActivityQueryResult:
        return self._query(query)

    def query_network(self, query: NetworkActivityQuery) -> ActivityQueryResult:
        return self._query(query)

    def query_socket(self, query: SocketActivityQuery) -> ActivityQueryResult:
        return self._query(query)

    def query_file(self, query: FileActivityQuery) -> ActivityQueryResult:
        return self._query(query)

    def query_service(self, query: ServiceActivityQuery) -> ActivityQueryResult:
        return self._query(query)

    def query_package(self, query: PackageActivityQuery) -> ActivityQueryResult:
        return self._query(query)

    def query_asset(self, query: AssetActivityQuery) -> ActivityQueryResult:
        return self._query(query)

    def query_extension(self, query: ExtensionActivityQuery) -> ActivityQueryResult:
        return self._query(query)

    def _query(self, query: ActivityQueryBase) -> ActivityQueryResult:
        scope_domain = _SCOPE_DOMAIN_BY_ACTIVITY[query.activity_type]
        if scope_domain != "extension" and scope_domain not in query.scope.allowed_domains:
            raise DataAccessError(f"Activity type {query.activity_type!r} is outside the authorized scope")
        requested_hosts = list(dict.fromkeys(query.host_refs or query.scope.host_ids))
        unauthorized = sorted(set(requested_hosts) - set(query.scope.host_ids))
        if unauthorized:
            raise DataAccessError(f"Hosts are outside the authorized scope: {unauthorized}")
        start = query.start_time or query.scope.start_time
        end = query.end_time or query.scope.end_time
        if query.scope.start_time and start and start < query.scope.start_time:
            raise DataAccessError("Requested start_time is outside the authorized scope")
        if query.scope.end_time and end and end > query.scope.end_time:
            raise DataAccessError("Requested end_time is outside the authorized scope")

        sql = (
            "SELECT observed_at, activity_id, source_system, payload_json "
            "FROM normalized_activities WHERE tenant_id=? AND activity_type=?"
        )
        args: list[Any] = [query.tenant_id, query.activity_type]
        if requested_hosts and query.activity_type != "asset":
            sql += f" AND host_ref IN ({','.join('?' for _ in requested_hosts)})"
            args.extend(requested_hosts)
        if start:
            sql += " AND observed_at>=?"
            args.append(start.isoformat())
        if end:
            sql += " AND observed_at<=?"
            args.append(end.isoformat())
        if self.visible_sources is not None:
            if not self.visible_sources:
                sql += " AND 1=0"
            else:
                sql += f" AND source_system IN ({','.join('?' for _ in self.visible_sources)})"
                args.extend(sorted(self.visible_sources))
        if query.cursor:
            cursor_time, cursor_id = _decode_cursor(query.cursor)
            sql += " AND (observed_at>? OR (observed_at=? AND activity_id>?))"
            args.extend([cursor_time, cursor_time, cursor_id])
        sql += " ORDER BY observed_at, activity_id"

        # Fetch extra rows because strong typed filters are applied after coarse indexed filters.
        resolved_entity_refs = self._resolve_entity_refs(query.tenant_id, query.entity_refs)
        rows = self.store.connection.execute(sql, args).fetchall()
        matched = []
        for row in rows:
            activity = _ACTIVITY_ADAPTER.validate_json(row["payload_json"])
            if self._matches(activity, query, resolved_entity_refs):
                matched.append(activity)
            if len(matched) > query.limit:
                break
        has_more = len(matched) > query.limit
        activities = matched[: query.limit]
        next_cursor = None
        if has_more and activities:
            last = activities[-1]
            next_cursor = _cursor(last.observed_at.isoformat(), last.activity_id)

        requested = self._scope_snapshot(query, query.start_time, query.end_time)
        applied = self._scope_snapshot(query, start, end, requested_hosts)
        definition = self._interface_definition(query)
        evidence = [self._evidence_reference(query, activity.activity_id, activity.observed_at) for activity in activities]
        boundary = QueryExecutionBoundary(
            interface_id=definition.interface_id,
            interface_version=definition.interface_version,
            requested_scope=requested,
            applied_scope=applied,
            returned_count=len(activities),
            page_limit=query.limit,
            next_cursor=next_cursor,
            source_systems=sorted({item.source_system for item in activities}),
            executed_at=datetime.now(timezone.utc),
        )
        return ActivityQueryResult(
            tenant_id=query.tenant_id,
            case_id=query.case_id,
            run_id=query.run_id,
            query_id=query.query_id,
            source_identity="sqlite-activity-query-adapter",
            interface_definition=definition,
            execution_boundary=boundary,
            activities=activities,
            evidence_references=evidence,
        )

    @staticmethod
    def _matches(activity, query: ActivityQueryBase, resolved_entity_refs: set[str]) -> bool:
        refs = _all_refs(activity)
        if query.entity_refs and not refs.intersection(resolved_entity_refs):
            return False
        if query.activity_type == "asset" and query.host_refs and not refs.intersection(query.host_refs):
            return False
        if query.source_event_types and _source_event_type(activity) not in query.source_event_types:
            return False
        mappings = {
            "process_refs": refs, "endpoint_refs": refs, "socket_refs": refs,
            "file_refs": refs, "service_refs": refs, "package_refs": refs,
            "asset_refs": refs,
        }
        for field, actual in mappings.items():
            requested = getattr(query, field, [])
            if requested and not actual.intersection(requested):
                return False
        operations = getattr(query, "operations", [])
        if operations and getattr(activity, "operation", None) not in operations:
            return False
        protocols = getattr(query, "protocols", [])
        if protocols and getattr(activity, "protocol", None) not in protocols:
            return False
        executable = getattr(query, "executable", None)
        if executable and getattr(activity, "executable", None) != executable:
            return False
        schemas = getattr(query, "extension_schemas", [])
        if schemas and getattr(activity, "extension_schema", None) not in schemas:
            return False
        return True

    def _resolve_entity_refs(self, tenant_id: str, entity_refs: list[str]) -> set[str]:
        if not entity_refs:
            return set()
        placeholders = ",".join("?" for _ in entity_refs)
        rows = self.store.connection.execute(
            f"SELECT payload_json FROM entity_identities WHERE tenant_id=? AND entity_id IN ({placeholders})",
            [tenant_id, *entity_refs],
        ).fetchall()
        resolved = set(entity_refs)
        for row in rows:
            payload = json.loads(row["payload_json"])
            resolved.update(str(alias["source_id"]) for alias in payload.get("aliases", []))
        return resolved

    @staticmethod
    def _scope_snapshot(query, start, end, hosts=None) -> QueryScopeSnapshot:
        filters: dict[str, Any] = {"activity_type": query.activity_type}
        for name in (
            "source_event_types", "process_refs", "endpoint_refs", "socket_refs", "file_refs",
            "service_refs", "package_refs", "asset_refs", "operations", "protocols",
            "extension_schemas",
        ):
            value = getattr(query, name, None)
            if value:
                filters[name] = list(value)
        if getattr(query, "executable", None):
            filters["executable"] = query.executable
        return QueryScopeSnapshot(
            host_refs=list(hosts if hosts is not None else query.host_refs),
            entity_refs=list(query.entity_refs), start_time=start, end_time=end, filters=filters,
        )

    @staticmethod
    def _interface_definition(query) -> QueryInterfaceDefinition:
        common_fields = [
            QueryFieldDefinition(name="activity_id", value_type="string", semantic="规范化活动唯一标识", nullable=False),
            QueryFieldDefinition(name="observed_at", value_type="datetime", semantic="来源系统记录的活动发生时间", nullable=False),
            QueryFieldDefinition(name="source_system", value_type="string", semantic="产生原始记录的来源系统", nullable=False),
            QueryFieldDefinition(name="subject_refs", value_type="array", semantic="活动涉及的来源实体引用", nullable=False),
            QueryFieldDefinition(name="raw_record_ref", value_type="string", semantic="受管原始记录引用", nullable=False),
        ]
        interface_id = f"activity-query/{query.activity_type}"
        specific_filters = {
            "process": ["process_refs", "operations", "executable"],
            "network": ["process_refs", "endpoint_refs", "protocols"],
            "socket": ["process_refs", "socket_refs"],
            "file": ["file_refs", "process_refs", "operations"],
            "service": ["service_refs", "operations"],
            "package": ["package_refs", "file_refs"],
            "asset": ["asset_refs"],
            "extension": ["extension_schemas"],
        }[query.activity_type]
        return QueryInterfaceDefinition(
            tenant_id=query.tenant_id,
            source_identity="activity-query-contract",
            interface_id=interface_id,
            interface_version=INTERFACE_VERSION,
            activity_types=[query.activity_type],
            fields=common_fields,
            supported_filters=[
                "host_refs", "entity_refs", "start_time", "end_time", "source_event_types",
                "cursor", "limit",
                *specific_filters,
            ],
            correlation_keys=["subject_refs", "actor_refs", "target_refs", "source_record_id"],
            max_page_size=1000,
            sort_order=["observed_at", "activity_id"],
        )

    @staticmethod
    def _evidence_reference(query, activity_id: str, observed_at: datetime) -> EvidenceReference:
        digest = hashlib.sha256(
            f"{query.tenant_id}:{query.case_id}:{query.run_id}:{query.query_id}:{activity_id}".encode()
        ).hexdigest()[:24]
        return EvidenceReference(
            tenant_id=query.tenant_id,
            case_id=query.case_id,
            run_id=query.run_id,
            query_id=query.query_id,
            evidence_id=f"evidence-ref-{digest}",
            activity_ref=activity_id,
            evidence_role_refs=[query.activity_type],
            observed_at=observed_at,
            source_identity="activity-query-adapter",
        )
