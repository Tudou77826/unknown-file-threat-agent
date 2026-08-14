from __future__ import annotations

from ..domain.models import (
    DataToolRequest,
    FinishRequest,
    InvestigationAction,
    InvestigationState,
    ScopeRequest,
)


class PolicyError(RuntimeError):
    pass


DATA_TOOL_NAMES = {
    "query_process_activities", "query_network_activities", "query_socket_activities",
    "query_file_activities", "query_service_activities", "query_package_activities",
    "query_asset_activities", "explore_entity", "get_raw_records", "calculate_activity_metrics",
}


def _known_refs(state: InvestigationState) -> set[str]:
    refs = set(state.tool_ledger.authorized_activity_refs)
    for result in state.tool_ledger.query_results:
        refs.update(item.evidence_id for item in result.evidence_references)
        refs.update(item.activity_id for item in result.activities)
    for result in state.tool_ledger.entity_results:
        if result.identity is not None:
            refs.add(result.identity.entity_id)
        refs.update(item.relation_id for item in result.resolved_relations)
        refs.update(item.relation_id for item in result.candidate_relations)
    return refs


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

    if isinstance(action, ScopeRequest):
        if state.scope.expansion_policy == "deny":
            raise PolicyError("Scope expansion is disabled by policy")
        if state.budget.scope_expansions_used >= state.budget.max_scope_expansions:
            raise PolicyError("Scope-expansion budget exhausted")
        duplicates = sorted(set(action.requested_host_ids) & set(state.scope.host_ids))
        if duplicates:
            raise PolicyError(f"Hosts are already in scope: {duplicates}")
        if len(set(action.requested_host_ids)) > 3:
            raise PolicyError("Scope request is not minimized; at most three candidate hosts are allowed")
        unsupported_domains = set(action.requested_domains) - set(state.scope.allowed_domains)
        if unsupported_domains:
            raise PolicyError(f"Scope request contains disallowed domains: {sorted(unsupported_domains)}")
        known = _known_refs(state)
        missing = sorted(set(action.reason_evidence_refs) - known)
        if missing:
            raise PolicyError(f"Scope request references unknown evidence: {missing}")
        return

    if isinstance(action, FinishRequest):
        return

    raise PolicyError(f"Unsupported investigation action: {type(action).__name__}")
