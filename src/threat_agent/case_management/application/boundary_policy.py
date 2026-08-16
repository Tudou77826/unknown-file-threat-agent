"""Single-host investigation boundary policy (Feature 13).

Implements the ``InvestigationBoundaryPort`` defined by the judgment module:
one server-fixed tenant, one immutable alert host per run, and a deploy-time
lookback window. The policy performs deterministic pre-call authorization and
post-execution result validation; anything it cannot prove is denied. It never
touches the data stores itself — host attribution of stored objects is enforced
by the data layer and the tool gateway.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from ...contracts import (
    ActivityQueryResult,
    ActivityMetricResult,
    BoundaryDenied,
    EntityExplorationResult,
    InvestigationToolLedger,
    RawRecordResult,
    ToolRuntimeContext,
)
from ...judgment.application.boundary import BoundaryViolationError

# Tool name -> authorized scope domain. Tools that operate purely on
# run-authorized references (exploration, raw records, metrics) are guarded by
# reference checks instead of a domain.
_TOOL_SCOPE_DOMAIN = {
    "query_process_activities": "process",
    "query_network_activities": "network",
    "query_socket_activities": "network",
    "query_file_activities": "file",
    "query_service_activities": "persistence",
    "query_package_activities": "reputation",
    "query_asset_activities": "reputation",
}

_REFERENCE_TOOLS = {
    "get_raw_records": "activity_refs",
    "calculate_activity_metrics": "activity_refs",
}


def _deny(tool_name: str, code: str, message: str, **ids: Any) -> None:
    raise BoundaryViolationError(BoundaryDenied(
        code=code, tool_name=tool_name, message=message, **ids,
    ))


def _as_datetime(value: Any) -> datetime | None:
    """Parse a boundary argument into an aware datetime, or None if unparseable.

    Naive timestamps are interpreted as UTC: scope bounds are always aware, and
    comparing the two kinds would raise instead of denying.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


class SingleHostBoundaryPolicy:
    """Authorize tool calls against a single alert host and a fixed identity."""

    def __init__(self, *, tenant_id: str, case_id: str, run_id: str):
        self.tenant_id = tenant_id
        self.case_id = case_id
        self.run_id = run_id

    # -- pre-call authorization -------------------------------------------

    def authorize_call(
        self,
        context: ToolRuntimeContext,
        ledger: InvestigationToolLedger,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> None:
        self._check_identity(context, tool_name)
        hosts = context.scope.host_ids
        if len(hosts) != 1:
            _deny(
                tool_name, "single_host_required",
                "调查边界要求 Scope 只包含唯一告警主机",
                host_refs=list(hosts),
            )
        domain = _TOOL_SCOPE_DOMAIN.get(tool_name)
        if domain is not None and domain not in context.scope.allowed_domains:
            _deny(
                tool_name, "domain_out_of_scope",
                f"工具数据域 {domain} 未在本次调查的授权范围内",
            )
        requested_hosts = [
            str(host) for host in (arguments.get("host_refs") or [])
        ]
        unauthorized_hosts = sorted(set(requested_hosts) - set(hosts))
        if unauthorized_hosts:
            _deny(
                tool_name, "host_out_of_scope",
                "请求主机超出唯一告警主机边界",
                host_refs=unauthorized_hosts,
            )
        self._check_time_window(context, tool_name, arguments)
        if tool_name == "explore_entity":
            entity_ref = str(arguments.get("entity_ref") or "")
            if entity_ref and entity_ref not in set(ledger.authorized_entity_refs):
                _deny(
                    tool_name, "entity_not_authorized",
                    "实体引用不在本次运行已授权的实体集合内",
                    reference_ids=[entity_ref],
                )
        ref_field = _REFERENCE_TOOLS.get(tool_name)
        if ref_field is not None:
            requested_refs = [str(ref) for ref in (arguments.get(ref_field) or [])]
            unauthorized = sorted(set(requested_refs) - set(ledger.authorized_activity_refs))
            if unauthorized:
                _deny(
                    tool_name, "reference_not_authorized",
                    "数据引用不属于本次运行已返回的活动",
                    reference_ids=unauthorized,
                )

    def _check_identity(self, context: ToolRuntimeContext, tool_name: str) -> None:
        # Identity mismatch is a wiring bug, not a model-facing boundary
        # denial: fail loudly instead of answering with a stable error code.
        if (
            context.tenant_id != self.tenant_id
            or context.case_id != self.case_id
            or context.run_id != self.run_id
        ):
            raise ValueError(
                "Tool runtime context does not match the server-side run identity "
                f"(expected tenant={self.tenant_id} case={self.case_id} run={self.run_id}, "
                f"got tenant={context.tenant_id} case={context.case_id} run={context.run_id} "
                f"for tool {tool_name})"
            )

    @staticmethod
    def _check_time_window(
        context: ToolRuntimeContext, tool_name: str, arguments: Mapping[str, Any]
    ) -> None:
        start = _as_datetime(arguments.get("start_time"))
        end = _as_datetime(arguments.get("end_time"))
        if start is not None and context.scope.start_time is not None and start < context.scope.start_time:
            _deny(tool_name, "time_out_of_scope", "请求开始时间早于授权时间窗口")
        if end is not None and context.scope.end_time is not None and end > context.scope.end_time:
            _deny(tool_name, "time_out_of_scope", "请求结束时间晚于授权时间窗口")

    # -- post-execution result validation ----------------------------------

    def validate_result(
        self,
        context: ToolRuntimeContext,
        ledger: InvestigationToolLedger,
        tool_name: str,
        result: Any,
    ) -> None:
        if isinstance(result, ActivityQueryResult):
            self._check_result_identity(context, tool_name, result)
            self._check_activities(context, tool_name, result.activities)
        elif isinstance(result, EntityExplorationResult):
            self._check_activities(context, tool_name, result.timeline)
        elif isinstance(result, RawRecordResult):
            unauthorized = sorted(
                {item.activity_ref for item in result.records}
                - set(ledger.authorized_activity_refs)
            )
            if unauthorized:
                _deny(
                    tool_name, "reference_not_authorized",
                    "原始记录引用不属于本次运行已返回的活动",
                    reference_ids=unauthorized,
                )
        elif isinstance(result, ActivityMetricResult):
            unauthorized = sorted(
                set(result.activity_refs) - set(ledger.authorized_activity_refs)
            )
            if unauthorized:
                _deny(
                    tool_name, "reference_not_authorized",
                    "指标计算引用不属于本次运行已返回的活动",
                    reference_ids=unauthorized,
                )

    @staticmethod
    def _check_result_identity(
        context: ToolRuntimeContext, tool_name: str, result: ActivityQueryResult
    ) -> None:
        if (
            result.tenant_id != context.tenant_id
            or result.case_id != context.case_id
            or result.run_id != context.run_id
        ):
            raise ValueError(
                f"Query result identity does not match the run context for tool {tool_name}"
            )

    @staticmethod
    def _check_activities(context: ToolRuntimeContext, tool_name: str, activities) -> None:
        for activity in activities:
            host = getattr(activity, "host_ref", None)
            if host is not None and host not in set(context.scope.host_ids):
                _deny(
                    tool_name, "host_out_of_scope",
                    "工具结果包含授权主机之外的活动",
                    host_refs=[str(host)],
                    reference_ids=[activity.activity_id],
                )
            if context.scope.start_time is not None and activity.observed_at < context.scope.start_time:
                _deny(
                    tool_name, "time_out_of_scope",
                    "工具结果包含授权时间窗口之外的活动",
                    reference_ids=[activity.activity_id],
                )
            if context.scope.end_time is not None and activity.observed_at > context.scope.end_time:
                _deny(
                    tool_name, "time_out_of_scope",
                    "工具结果包含授权时间窗口之外的活动",
                    reference_ids=[activity.activity_id],
                )
