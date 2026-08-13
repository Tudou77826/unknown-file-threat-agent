from __future__ import annotations

import hashlib
import math
import time
from collections import Counter, defaultdict
from datetime import datetime
from statistics import mean, pstdev
from typing import Any, Callable

from ...contracts import (
    ActivityMetricResult,
    AssetActivityQuery,
    CalculateActivityMetricsInput,
    EntityExplorationResult,
    ExploreEntityInput,
    ExtensionActivityQuery,
    FileActivityQuery,
    GetRawRecordsInput,
    InvestigationToolLedger,
    InvestigationToolTrace,
    NetworkActivityQuery,
    PackageActivityQuery,
    ProcessActivityQuery,
    QueryActivitiesInput,
    RawRecordResult,
    RawRecordView,
    ServiceActivityQuery,
    SocketActivityQuery,
    ToolRuntimeContext,
)
from ...data_foundation import DataAccessError, SQLiteActivityQueryAdapter, SQLiteActivityStore


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


_FILTERS = {
    "process": {"source_event_types", "process_refs", "operations", "executable"},
    "network": {"source_event_types", "process_refs", "endpoint_refs", "protocols"},
    "socket": {"source_event_types", "process_refs", "socket_refs"},
    "file": {"source_event_types", "file_refs", "process_refs", "operations"},
    "service": {"source_event_types", "service_refs", "operations"},
    "package": {"source_event_types", "package_refs", "file_refs"},
    "asset": {"source_event_types", "asset_refs"},
    "extension": {"source_event_types", "extension_schemas"},
}


class InvestigationToolGateway:
    """Four stable LLM tools over typed data-foundation capabilities."""

    tool_names = (
        "query_activities", "explore_entity", "get_raw_records", "calculate_activity_metrics"
    )

    def __init__(
        self,
        store: SQLiteActivityStore,
        query_adapter: SQLiteActivityQueryAdapter,
        event_sink: Callable[[str, str, dict[str, Any] | None], None] | None = None,
    ):
        self.store = store
        self.query_adapter = query_adapter
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
        handler = getattr(self, tool_name)
        started = time.perf_counter()
        result = handler(arguments, context, ledger)
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

    @staticmethod
    def _event_details(tool_name: str, arguments: dict[str, Any], result: Any) -> dict[str, Any]:
        details: dict[str, Any] = {
            "tool_name": tool_name,
            "activity_type": arguments.get("activity_type"),
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

    def query_activities(self, raw, context, ledger):
        request = QueryActivitiesInput.model_validate(raw)
        unsupported = sorted(set(request.filters) - _FILTERS[request.activity_type])
        if unsupported:
            raise DataAccessError(
                f"Unsupported filters for {request.activity_type}: {unsupported}"
            )
        fingerprint = hashlib.sha256(
            f"{context.run_id}:{len(ledger.query_results)}:{request.model_dump_json()}".encode()
        ).hexdigest()[:16]
        query = _QUERY_CLASSES[request.activity_type](
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
            **request.filters,
        )
        result = getattr(self.query_adapter, f"query_{request.activity_type}")(query)
        ledger.query_results.append(result)
        ledger.authorized_activity_refs = sorted(set(ledger.authorized_activity_refs) | {
            item.activity_id for item in result.activities
        })
        return result

    def explore_entity(self, raw, context, ledger):
        request = ExploreEntityInput.model_validate(raw)
        identity = self.store.get_entity(context.tenant_id, request.entity_ref)
        if identity is None:
            raise DataAccessError("Unknown entity reference")
        relations = self.store.find_relations(
            context.tenant_id, request.entity_ref, request.relation_direction
        ) if "relations" in request.include else []
        alias_refs = {item.source_id for item in identity.aliases}
        timeline = []
        if "timeline" in request.include:
            for activity in self.store.list_activities(context.tenant_id):
                refs = set(activity.subject_refs) | set(activity.actor_refs) | set(activity.target_refs)
                if not refs.intersection(alias_refs):
                    continue
                if request.start_time and activity.observed_at < request.start_time:
                    continue
                if request.end_time and activity.observed_at > request.end_time:
                    continue
                timeline.append(activity)
        offset = self._decode_offset(request.cursor)
        page = timeline[offset:offset + request.limit]
        next_cursor = str(offset + request.limit) if offset + request.limit < len(timeline) else None
        result = EntityExplorationResult(
            identity=identity if "identity" in request.include else None,
            resolved_relations=[item for item in relations if item.resolution_status == "resolved"],
            candidate_relations=[item for item in relations if item.resolution_status == "candidate"],
            timeline=page,
            returned_count=len(page),
            next_cursor=next_cursor,
        )
        ledger.entity_results.append(result)
        ledger.authorized_activity_refs = sorted(
            set(ledger.authorized_activity_refs) | {item.activity_id for item in page}
        )
        return result

    def get_raw_records(self, raw, context, ledger):
        request = GetRawRecordsInput.model_validate(raw)
        unauthorized = sorted(set(request.activity_refs) - set(ledger.authorized_activity_refs))
        if unauthorized:
            raise DataAccessError(
                f"Raw records require activity references already returned in this run: {unauthorized}"
            )
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
        ledger.raw_record_results.append(result)
        return result

    def calculate_activity_metrics(self, raw, context, ledger):
        request = CalculateActivityMetricsInput.model_validate(raw)
        unauthorized = sorted(set(request.activity_refs) - set(ledger.authorized_activity_refs))
        if unauthorized:
            raise DataAccessError(
                f"Metrics require activity references already returned in this run: {unauthorized}"
            )
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
        ledger.metric_results.append(result)
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
        current: Any = payload
        for part in path.strip(".").split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

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
