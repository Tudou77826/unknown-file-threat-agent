from __future__ import annotations

from ..domain.models import (
    DataToolRequest,
    FinishRequest,
    InvestigationAction,
    InvestigationState,
)


class PolicyError(RuntimeError):
    pass


DATA_TOOL_NAMES = {
    "query_process_activities", "query_network_activities", "query_socket_activities",
    "query_file_activities", "query_service_activities", "query_package_activities",
    "query_asset_activities", "explore_entity", "get_raw_records", "calculate_activity_metrics",
}


def validate_action(
    action: InvestigationAction,
    state: InvestigationState,
    *,
    data_tool_mode: bool = True,
) -> None:
    if (
        state.budget.iterations_used >= state.budget.max_iterations
        and not isinstance(action, FinishRequest)
    ):
        raise PolicyError("Iteration budget exhausted")

    if isinstance(action, DataToolRequest):
        if action.tool_name not in DATA_TOOL_NAMES:
            raise PolicyError(f"Unknown LLM data tool: {action.tool_name}")
        return

    if isinstance(action, FinishRequest):
        return

    raise PolicyError(f"Unsupported investigation action: {type(action).__name__}")
