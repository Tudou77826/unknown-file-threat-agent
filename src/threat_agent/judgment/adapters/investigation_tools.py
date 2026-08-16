from __future__ import annotations

import hashlib
import math
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from statistics import mean, pstdev
from typing import Any, Callable

from ...contracts import (
    ActivityMetricResult,
    AssetActivitiesInput,
    AssetActivityQuery,
    BoundaryDenied,
    CalculateActivityMetricsInput,
    EntityExplorationResult,
    ExploreEntityInput,
    ExtensionActivityQuery,
    FileActivitiesInput,
    FileActivityQuery,
    GetRawRecordsInput,
    InvestigationToolLedger,
    InvestigationToolTrace,
    NetworkActivitiesInput,
    NetworkActivityQuery,
    OutOfScopeRelationClue,
    PackageActivitiesInput,
    PackageActivityQuery,
    ProcessActivitiesInput,
    ProcessActivityQuery,
    RawRecordResult,
    RawRecordView,
    ServiceActivitiesInput,
    ServiceActivityQuery,
    SocketActivitiesInput,
    SocketActivityQuery,
    ToolRuntimeContext,
)
from ...data_foundation import DataAccessError, SQLiteActivityQueryAdapter, SQLiteActivityStore
from ..application.boundary import BoundaryViolationError, InvestigationBoundaryPort


_QUERY_CLASSES = {
    "process": ProcessActivityQuery,
    "network": NetworkActivityQuery,
    "socket": SocketActivityQuery,
    "file": FileActivityQuery,
    "service": ServiceActivityQuery,
    "package": PackageActivityQuery,
    "asset": AssetActivityQuery,
    "extension": ExtensionActivityQuery,
}

# Each domain tool has a fixed input schema whose fields are exactly the ones
# the domain query accepts. The domain is encoded in the tool name, so there is
# no "cross-domain rejection": fields of another domain simply do not exist.
_DOMAIN_TOOLS = {
    "query_process_activities": ("process", ProcessActivitiesInput),
    "query_network_activities": ("network", NetworkActivitiesInput),
    "query_socket_activities": ("socket", SocketActivitiesInput),
    "query_file_activities": ("file", FileActivitiesInput),
    "query_service_activities": ("service", ServiceActivitiesInput),
    "query_package_activities": ("package", PackageActivitiesInput),
    "query_asset_activities": ("asset", AssetActivitiesInput),
}

# The model occasionally emits the literal string "null" (or "none"/"") for an
# optional filter it does not want to use. Downstream strong-typed filtering
# treats a non-empty string as a real value, so "null" would silently filter
# every row out. Normalize those tokens to None before validation.
_NULL_LIKE = {"", "null", "none", "undefined", "nan"}


def _normalize_null_values(value: Any) -> Any:
    if isinstance(value, str):
        return None if value.strip().lower() in _NULL_LIKE else value
    if isinstance(value, list):
        return [item for item in (_normalize_null_values(v) for v in value) if item is not None]
    if isinstance(value, dict):
        return {
            key: item
            for key, val in value.items()
            if (item := _normalize_null_values(val)) is not None
        }
    return value


def _normalize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    return _normalize_null_values(arguments) or {}


def _aware(value: datetime | None) -> datetime | None:
    """Interpret naive datetimes as UTC so they compare with aware scope bounds."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class InvestigationToolGateway:
    """Stable LLM tools over typed data-foundation capabilities.

    Every invocation passes the injected ``InvestigationBoundaryPort`` twice:
    before execution (authorization) and after execution (result validation).
    Ledger mutations happen only after both checks pass, so an out-of-boundary
    result can never reach the ledger, events or the model context.
    """

    tool_names = (
        "query_process_activities",
        "query_network_activities",
        "query_socket_activities",
        "query_file_activities",
        "query_service_activities",
        "query_package_activities",
        "query_asset_activities",
        "explore_entity",
        "get_raw_records",
        "calculate_activity_metrics",
    )

    def __init__(
        self,
        store: SQLiteActivityStore,
        query_adapter: SQLiteActivityQueryAdapter,
        boundary: InvestigationBoundaryPort,
        event_sink: Callable[[str, str, dict[str, Any] | None], None] | None = None,
    ):
        self.store = store
        self.query_adapter = query_adapter
        self.boundary = boundary
        self.event_sink = event_sink or (lambda _kind, _message, _details=None: None)

    def invoke(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: ToolRuntimeContext,
        ledger: InvestigationToolLedger,
        *,
        tool_call_id: str | None = None,
        model_message: dict[str, Any] | None = None,
    ) -> Any:
        if tool_name not in self.tool_names:
            raise KeyError(f"Unknown investigation data tool: {tool_name}")
        arguments = _normalize_arguments(dict(arguments or {}))
        handler = getattr(self, tool_name)
        started = time.perf_counter()
        try:
            self.boundary.authorize_call(context, ledger, tool_name, arguments)
            result = handler(arguments, context, ledger)
            self.boundary.validate_result(context, ledger, tool_name, result)
        except BoundaryViolationError as violation:
            self._emit_denial(violation.denial, context)
            raise
        self._record_result(context, ledger, tool_name, result)
        ledger.traces.append(InvestigationToolTrace(
            sequence=len(ledger.traces) + 1,
            tool_name=tool_name,
            arguments=arguments,
            result_type=type(result).__name__,
            result=result.model_dump(mode="json"),
            tool_call_id=tool_call_id,
            model_message=model_message or {},
        ))
        event_details = self._event_details(tool_name, arguments, result)
        event_details["node"] = "execute"
        event_details["arguments"] = arguments
        event_details["result"] = result.model_dump(mode="json")
        event_details["tool_call_id"] = tool_call_id
        event_details["duration_ms"] = round(
            (time.perf_counter() - started) * 1000, 3
        )
        self.event_sink(
            "tool",
            f"数据工具 {tool_name} 调用完成",
            event_details,
        )
        return result

    def _emit_denial(self, denial: BoundaryDenied, context: ToolRuntimeContext) -> None:
        # Identifiers and scope summary only; unauthorized object content must
        # not leak into events or audit.
        self.event_sink("tool_error", f"调查边界拒绝工具调用：{denial.tool_name}", {
            "tool_name": denial.tool_name,
            "error_code": denial.code,
            "boundary_denied": denial.model_dump(mode="json"),
            "tenant_id": context.tenant_id,
            "case_id": context.case_id,
            "run_id": context.run_id,
            "scope": context.scope.model_dump(mode="json"),
            "node": "execute",
        })

    def _record_result(
        self, context: ToolRuntimeContext, ledger: InvestigationToolLedger,
        tool_name: str, result: Any,
    ) -> None:
        """Commit a validated result and extend the run's authorized ref sets."""

        def extend_activities(activities) -> None:
            for activity in activities:
                refs = set(activity.subject_refs) | set(activity.actor_refs) | set(activity.target_refs)
                ledger.authorized_entity_refs = sorted(
                    set(ledger.authorized_entity_refs) | refs
                )
            ledger.authorized_activity_refs = sorted(
                set(ledger.authorized_activity_refs)
                | {item.activity_id for item in activities}
            )

        def endpoint_refs_of(relation) -> set[str]:
            refs: set[str] = set()
            for endpoint in (relation.source_entity_ref, relation.target_entity_ref):
                identity = self._resolve_identity_of_ref(context.tenant_id, endpoint)
                if identity is None:
                    refs.add(endpoint)
                else:
                    refs.add(identity.entity_id)
                    refs.update(alias.source_id for alias in identity.aliases)
            return refs

        if tool_name in _DOMAIN_TOOLS:
            ledger.query_results.append(result)
            extend_activities(result.activities)
        elif tool_name == "explore_entity":
            ledger.entity_results.append(result)
            extend_activities(result.timeline)
            entity_refs = set()
            if result.identity is not None:
                entity_refs.add(result.identity.entity_id)
                entity_refs.update(alias.source_id for alias in result.identity.aliases)
            for relation in [*result.resolved_relations, *result.candidate_relations]:
                entity_refs |= endpoint_refs_of(relation)
            ledger.authorized_entity_refs = sorted(
                set(ledger.authorized_entity_refs) | entity_refs
            )
        elif tool_name == "get_raw_records":
            ledger.raw_record_results.append(result)
        elif tool_name == "calculate_activity_metrics":
            ledger.metric_results.append(result)

    @staticmethod
    def _event_details(tool_name: str, arguments: dict[str, Any], result: Any) -> dict[str, Any]:
        # The domain is fixed by the tool name; arguments no longer carry an
        # activity_type field after the feature-09 split.
        domain = _DOMAIN_TOOLS.get(tool_name, (None, None))[0]
        details: dict[str, Any] = {
            "tool_name": tool_name,
            "activity_type": domain,
            "operation": arguments.get("operation"),
        }
        if hasattr(result, "query_id"):
            details["query_id"] = result.query_id
        if hasattr(result, "returned_count"):
            details["returned_count"] = result.returned_count
        elif hasattr(result, "execution_boundary"):
            details["returned_count"] = result.execution_boundary.returned_count
        if hasattr(result, "activities"):
            details["evidence_ids"] = [
                item.activity_id for item in result.activities[:20]
            ]
        elif hasattr(result, "timeline"):
            details["evidence_ids"] = [
                item.activity_id for item in result.timeline[:20]
            ]
        elif hasattr(result, "activity_refs"):
            details["evidence_ids"] = list(result.activity_refs[:20])
        elif hasattr(result, "records"):
            details["evidence_ids"] = [
                item.activity_ref for item in result.records[:20]
            ]
            details["returned_count"] = len(result.records)
        return {key: value for key, value in details.items() if value is not None}

    def _query_domain(self, activity_type: str, request, context, ledger):
        fingerprint = hashlib.sha256(
            f"{context.run_id}:{len(ledger.query_results)}:{request.model_dump_json()}".encode()
        ).hexdigest()[:16]
        query = _QUERY_CLASSES[activity_type](
            tenant_id=context.tenant_id,
            case_id=context.case_id,
            source_identity="investigation-tool-gateway",
            run_id=context.run_id,
            query_id=f"activity-query-{fingerprint}",
            scope=context.scope,
            host_refs=request.host_refs,
            entity_refs=request.entity_refs,
            start_time=request.start_time,
            end_time=request.end_time,
            cursor=request.cursor,
            limit=request.limit,
            source_event_types=request.source_event_types,
            **{
                key: value
                for key, value in request.model_dump().items()
                if key
                not in {
                    "host_refs",
                    "entity_refs",
                    "start_time",
                    "end_time",
                    "cursor",
                    "limit",
                    "source_event_types",
                }
            },
        )
        return getattr(self.query_adapter, f"query_{activity_type}")(query)

    def query_process_activities(self, raw, context, ledger):
        request = ProcessActivitiesInput.model_validate(raw)
        return self._query_domain("process", request, context, ledger)

    def query_network_activities(self, raw, context, ledger):
        request = NetworkActivitiesInput.model_validate(raw)
        return self._query_domain("network", request, context, ledger)

    def query_socket_activities(self, raw, context, ledger):
        request = SocketActivitiesInput.model_validate(raw)
        return self._query_domain("socket", request, context, ledger)

    def query_file_activities(self, raw, context, ledger):
        request = FileActivitiesInput.model_validate(raw)
        return self._query_domain("file", request, context, ledger)

    def query_service_activities(self, raw, context, ledger):
        request = ServiceActivitiesInput.model_validate(raw)
        return self._query_domain("service", request, context, ledger)

    def query_package_activities(self, raw, context, ledger):
        request = PackageActivitiesInput.model_validate(raw)
        return self._query_domain("package", request, context, ledger)

    def query_asset_activities(self, raw, context, ledger):
        request = AssetActivitiesInput.model_validate(raw)
        return self._query_domain("asset", request, context, ledger)

    def explore_entity(self, raw, context, ledger):
        request = ExploreEntityInput.model_validate(raw)
        identity = self._resolve_identity(context.tenant_id, request.entity_ref)
        if identity is None:
            raise DataAccessError("Unknown entity reference")
        entity_id = identity.entity_id
        relations = self.store.find_relations(
            context.tenant_id, entity_id, request.relation_direction
        ) if "relations" in request.include else []
        resolved, candidate, out_of_scope = self._split_relations_by_host(
            context, relations, entity_id
        )
        alias_refs = {item.source_id for item in identity.aliases} | {entity_id}
        timeline = []
        if "timeline" in request.include:
            lower = max(
                filter(None, [context.scope.start_time, _aware(request.start_time)]),
                default=None,
            )
            upper = min(
                filter(None, [context.scope.end_time, _aware(request.end_time)]),
                default=None,
            )
            for activity in self.store.list_activities(context.tenant_id):
                refs = set(activity.subject_refs) | set(activity.actor_refs) | set(activity.target_refs)
                if not refs.intersection(alias_refs):
                    continue
                # Entity timelines must not carry other hosts' activities: a
                # shared entity (e.g. an external endpoint) is reachable from
                # the alert host, but the timeline stays on the alert host.
                activity_host = getattr(activity, "host_ref", None)
                if activity_host is not None and activity_host not in context.scope.host_ids:
                    continue
                if lower is not None and activity.observed_at < lower:
                    continue
                if upper is not None and activity.observed_at > upper:
                    continue
                timeline.append(activity)
        offset = self._decode_offset(request.cursor)
        page = timeline[offset:offset + request.limit]
        next_cursor = str(offset + request.limit) if offset + request.limit < len(timeline) else None
        result = EntityExplorationResult(
            identity=identity if "identity" in request.include else None,
            resolved_relations=resolved,
            candidate_relations=candidate,
            out_of_scope_relations=out_of_scope,
            timeline=page,
            returned_count=len(page),
            next_cursor=next_cursor,
        )
        return result

    def _split_relations_by_host(self, context, relations, entity_id):
        """Split relations into local ones and minimal cross-host clues.

        An endpoint whose host attribution can be determined and is not the
        alert host is returned as an identifier-only clue: no target
        attributes, no relation expansion, no target-side timeline.
        """
        resolved: list = []
        candidate: list = []
        out_of_scope: list[OutOfScopeRelationClue] = []
        local_hosts = set(context.scope.host_ids)
        for relation in relations:
            other = (
                relation.target_entity_ref
                if relation.source_entity_ref == entity_id
                else relation.source_entity_ref
            )
            if self._endpoint_host(context, other) not in local_hosts | {None}:
                out_of_scope.append(OutOfScopeRelationClue(
                    relation_id=relation.relation_id,
                    other_endpoint_ref=other,
                ))
                continue
            if relation.resolution_status == "resolved":
                resolved.append(relation)
            else:
                candidate.append(relation)
        return resolved, candidate, out_of_scope

    def _endpoint_host(self, context, endpoint_ref: str) -> str | None:
        """Deterministically attribute an endpoint ref to a host, if possible.

        Returns None when the ref carries no host attribution (shared entities
        such as external endpoints or packages).
        """
        identity = self._resolve_identity_of_ref(context.tenant_id, endpoint_ref)
        if identity is not None:
            if identity.attributes.get("host_ref"):
                return str(identity.attributes["host_ref"])
            if identity.entity_type == "host":
                for alias in identity.aliases:
                    source = alias.source_id
                    if source in context.scope.host_ids:
                        return source
                    if source.startswith("host:") and source[5:] in context.scope.host_ids:
                        return source[5:]
                return None
            for alias in identity.aliases:
                source = alias.source_id
                for host in context.scope.host_ids:
                    if source == host or source == f"host:{host}" or f":{host}:" in source:
                        return host
            return None
        # Unresolvable opaque refs fall back to structural attribution.
        for host in context.scope.host_ids:
            if endpoint_ref == host or endpoint_ref == f"host:{host}" or f":{host}:" in endpoint_ref:
                return host
        if endpoint_ref.startswith(("process:", "file:", "host:")) and endpoint_ref.count(":") >= 2:
            return endpoint_ref.split(":")[1]
        return None

    def _resolve_identity(self, tenant_id: str, ref: str):
        """Resolve an entity by entity_id first, then by alias source_id.

        Activity results expose aliases (e.g. ``process:host:pid:start``) while
        relations and identities are keyed by platform entity_id. Accept either.
        Host refs may appear as ``host:server-01`` (subject_ref) or ``server-01``
        (host_ref alias), so also retry with the ``host:`` prefix stripped.
        """
        for candidate in {ref, ref[5:] if ref.startswith("host:") else ref}:
            identity = self._resolve_identity_of_ref(tenant_id, candidate)
            if identity is not None:
                return identity
        return None

    def _resolve_identity_of_ref(self, tenant_id: str, ref: str):
        identity = self.store.get_entity(tenant_id, ref)
        if identity is not None:
            return identity
        for identity in self.store.list_entities(tenant_id):
            if any(alias.source_id == ref for alias in identity.aliases):
                return identity
        return None

    def get_raw_records(self, raw, context, ledger):
        request = GetRawRecordsInput.model_validate(raw)
        records = []
        for activity_ref in request.activity_refs[:request.max_records]:
            activity = self.store.get_activity(context.tenant_id, activity_ref)
            if activity is None:
                raise DataAccessError(f"Unknown activity reference: {activity_ref}")
            payload = self.store.get_raw_payload(context.tenant_id, activity.raw_record_ref)
            if payload is None:
                raise DataAccessError(f"Raw record is unavailable for activity: {activity_ref}")
            if request.field_paths:
                payload = {
                    path: value for path in request.field_paths
                    if (value := self._field_path(payload, path)) is not None
                }
            records.append(RawRecordView(
                activity_ref=activity_ref,
                raw_record_ref=activity.raw_record_ref,
                source_system=activity.source_system,
                source_record_id=activity.source_record_id,
                observed_at=activity.observed_at,
                payload=payload,
            ))
        result = RawRecordResult(
            records=records,
            truncated=len(request.activity_refs) > request.max_records,
        )
        return result

    def calculate_activity_metrics(self, raw, context, ledger):
        request = CalculateActivityMetricsInput.model_validate(raw)
        activities = [self.store.get_activity(context.tenant_id, ref) for ref in request.activity_refs]
        if any(item is None for item in activities):
            raise DataAccessError("Metric input contains an unknown activity reference")
        actual = [item for item in activities if item is not None]
        calculators = {
            "process_tree": self._process_tree,
            "connection_pattern": self._connection_pattern,
            "transfer_summary": self._transfer_summary,
            "file_change_summary": self._file_change_summary,
        }
        metrics, limitations = calculators[request.operation](actual)
        result = ActivityMetricResult(
            operation=request.operation,
            activity_refs=request.activity_refs,
            metrics=metrics,
            limitations=limitations,
        )
        return result

    @staticmethod
    def _process_tree(activities):
        edges = [
            {"parent_process_ref": item.parent_process_ref, "process_ref": item.process_ref}
            for item in activities
            if item.activity_type == "process" and item.parent_process_ref
        ]
        return {"edge_count": len(edges), "edges": edges}, []

    @staticmethod
    def _connection_pattern(activities):
        grouped = defaultdict(list)
        for item in activities:
            if item.activity_type == "network":
                grouped[item.destination_endpoint_ref or "unknown"].append(item.observed_at)
        result = {}
        for endpoint, times in grouped.items():
            ordered = sorted(times)
            intervals = [(b - a).total_seconds() for a, b in zip(ordered, ordered[1:])]
            result[endpoint] = {
                "connection_count": len(ordered),
                "average_interval_seconds": mean(intervals) if intervals else None,
                "interval_standard_deviation": pstdev(intervals) if len(intervals) > 1 else None,
            }
        return {"endpoints": result}, []

    @staticmethod
    def _transfer_summary(activities):
        sends = [item.byte_count for item in activities if item.activity_type == "socket" and item.direction == "send" and item.byte_count is not None]
        receives = [item.byte_count for item in activities if item.activity_type == "socket" and item.direction == "receive" and item.byte_count is not None]
        return {
            "sent_bytes": sum(sends), "received_bytes": sum(receives),
            "send_events": len(sends), "receive_events": len(receives),
        }, []

    @staticmethod
    def _file_change_summary(activities):
        files = [item for item in activities if item.activity_type == "file"]
        operations = Counter(item.operation for item in files)
        directories = Counter(
            item.path.rsplit("/", 1)[0] if item.path and "/" in item.path else item.path or "unknown"
            for item in files
        )
        return {
            "activity_count": len(files), "operation_counts": dict(operations),
            "directory_counts": dict(directories),
        }, []

    @staticmethod
    def _field_path(payload: dict[str, Any], path: str):
        # Raw records are event envelopes whose business fields live under
        # ``data``. Models ask for bare field names ("remote_ip"), so retry a
        # missed top-level path under the ``data.`` prefix instead of silently
        # returning an empty payload.
        def walk(candidate: str):
            current: Any = payload
            for part in candidate.strip(".").split("."):
                if not isinstance(current, dict) or part not in current:
                    return None
                current = current[part]
            return current

        value = walk(path)
        if value is None and not path.startswith("data."):
            value = walk(f"data.{path}")
        return value

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
