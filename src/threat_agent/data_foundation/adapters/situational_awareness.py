"""Compose source-specific database/IR reads behind the standard data port.

Handlers perform the source-specific reads and field mapping. They may use a
database, IR, or both; callers receive the same typed results in each case.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import ParamSpec, TypeVar

from ...contracts import (
    ActivityQueryResult, AssetActivityQuery, AuthenticationActivityQuery,
    EntityIdentity, ExtensionActivityQuery, FileActivityQuery, NetworkActivityQuery,
    NormalizedActivity, ObservedRelation, PackageActivityQuery, ProcessActivityQuery,
    ServiceActivityQuery, SocketActivityQuery,
)
from ...contracts.situational_awareness import (
    AlertQuery, AssessmentQuery, AssetInfo, DataQueryContext, FileHash,
    FileReputation, QueryPage, SourceAssessment, UnknownFileAlert,
)
from ..ports.evidence_query import DataAccessError, DataQueryFailed, UnsupportedDataQuery
from ..ports.investigation_data import (
    ActivityRawRecord, EntityTimelinePage, EntityTimelineQuery, InvestigationDataPort,
)


P = ParamSpec("P")
R = TypeVar("R")


class SituationalAwarenessDataAdapter:
    """Use an activity provider plus independently supplied context queries.

    Source-specific implementations are injected once at the composition root.
    Missing capabilities fail explicitly, and source failures never become
    empty records. Shared providers remain owned by the caller.
    """

    def __init__(
        self,
        activities: InvestigationDataPort | None = None,
        *,
        alerts: Callable[[AlertQuery], QueryPage[UnknownFileAlert]] | None = None,
        file_reputation: Callable[[DataQueryContext, FileHash], FileReputation] | None = None,
        asset_info: Callable[[DataQueryContext, str], AssetInfo | None] | None = None,
        source_assessments: Callable[[AssessmentQuery], QueryPage[SourceAssessment]] | None = None,
    ):
        self._activities = activities
        self._alerts = alerts
        self._file_reputation = file_reputation
        self._asset_info = asset_info
        self._source_assessments = source_assessments

    @staticmethod
    def _call(operation: str, handler: Callable[P, R] | None, *args: P.args, **kwargs: P.kwargs) -> R:
        if handler is None:
            raise UnsupportedDataQuery(f"Source does not support {operation}")
        try:
            return handler(*args, **kwargs)
        except DataAccessError:
            raise
        except Exception as error:
            raise DataQueryFailed(f"Source query failed: {operation}") from error

    def _read(self, operation: str, *args):
        return self._call(operation, getattr(self._activities, operation, None), *args)

    def query_process(self, query: ProcessActivityQuery) -> ActivityQueryResult:
        return self._read("query_process", query)

    def query_authentication(self, query: AuthenticationActivityQuery) -> ActivityQueryResult:
        return self._read("query_authentication", query)

    def query_file(self, query: FileActivityQuery) -> ActivityQueryResult:
        return self._read("query_file", query)

    def query_network(self, query: NetworkActivityQuery) -> ActivityQueryResult:
        return self._read("query_network", query)

    def query_socket(self, query: SocketActivityQuery) -> ActivityQueryResult:
        return self._read("query_socket", query)

    def query_service(self, query: ServiceActivityQuery) -> ActivityQueryResult:
        return self._read("query_service", query)

    def query_package(self, query: PackageActivityQuery) -> ActivityQueryResult:
        return self._read("query_package", query)

    def query_asset(self, query: AssetActivityQuery) -> ActivityQueryResult:
        return self._read("query_asset", query)

    def query_extension(self, query: ExtensionActivityQuery) -> ActivityQueryResult:
        return self._read("query_extension", query)

    def resolve_entity(self, tenant_id: str, entity_ref: str) -> EntityIdentity | None:
        return self._read("resolve_entity", tenant_id, entity_ref)

    def find_relations(
        self, tenant_id: str, entity_id: str, direction: str = "both"
    ) -> list[ObservedRelation]:
        return self._read("find_relations", tenant_id, entity_id, direction)

    def list_entity_timeline(self, query: EntityTimelineQuery) -> EntityTimelinePage:
        return self._read("list_entity_timeline", query)

    def get_activities(
        self, tenant_id: str, activity_refs: list[str]
    ) -> list[NormalizedActivity | None]:
        return self._read("get_activities", tenant_id, activity_refs)

    def get_raw_record(self, tenant_id: str, activity_ref: str) -> ActivityRawRecord | None:
        return self._read("get_raw_record", tenant_id, activity_ref)

    def query_alerts(self, query: AlertQuery) -> QueryPage[UnknownFileAlert]:
        page = self._call("query_alerts", self._alerts, query)
        for record in page.records:
            self._check_scope(query, record)
        return page

    def query_file_reputation(self, context: DataQueryContext, file_hash: FileHash) -> FileReputation:
        result = self._call("query_file_reputation", self._file_reputation, context, file_hash)
        self._check_scope(context, result)
        if result.file_hash != file_hash:
            raise DataAccessError("File reputation does not match the requested hash")
        return result

    def get_asset_info(self, context: DataQueryContext, host_ref: str) -> AssetInfo | None:
        if host_ref not in context.scope.host_ids:
            raise DataAccessError("Asset host is outside the authorized scope")
        result = self._call("get_asset_info", self._asset_info, context, host_ref)
        if result is not None:
            self._check_scope(context, result)
            if result.host_ref != host_ref:
                raise DataAccessError("Asset result does not match the requested host")
        return result

    def query_source_assessments(self, query: AssessmentQuery) -> QueryPage[SourceAssessment]:
        page = self._call("query_source_assessments", self._source_assessments, query)
        for record in page.records:
            self._check_scope(query, record)
        return page

    @staticmethod
    def _check_scope(context: DataQueryContext, record) -> None:
        if record.tenant_id != context.tenant_id:
            raise DataAccessError("Source result is outside the authorized tenant")
        host_ref = getattr(record, "host_ref", None)
        if host_ref is not None and host_ref not in context.scope.host_ids:
            raise DataAccessError("Source result is outside the authorized host scope")
