from __future__ import annotations

from datetime import datetime

from .models import AnalysisRequest, EvidenceRequest, FinishRequest, InvestigationAction, InvestigationState, ScopeRequest
from .tools import ToolRegistry


class PolicyError(RuntimeError):
    pass


def _datetime(value):
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyError(f"Invalid datetime parameter: {value}") from exc


def _contains_host(value, host_id: str) -> bool:
    if isinstance(value, str):
        return value == host_id or f":{host_id}:" in value or value.endswith(f":{host_id}")
    if isinstance(value, dict):
        return any(_contains_host(item, host_id) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_host(item, host_id) for item in value)
    return False


def validate_action(action: InvestigationAction, state: InvestigationState, registry: ToolRegistry) -> None:
    if state.budget.iterations_used >= state.budget.max_iterations:
        raise PolicyError("Iteration budget exhausted")
    evidence_by_id = {e.evidence_id: e for e in state.evidence}
    gaps_by_id = {g.gap_id: g for g in state.evidence_gaps}

    if isinstance(action, (EvidenceRequest, AnalysisRequest)):
        tool = registry.get(action.tool_name)
        expected = "evidence" if isinstance(action, EvidenceRequest) else "analysis"
        if tool.kind != expected:
            raise PolicyError(f"{action.tool_name} is not an {expected} tool")
        if tool.domain not in state.scope.allowed_domains and tool.domain != "execution":
            raise PolicyError(f"Domain {tool.domain} is outside scope")
        if state.budget.tool_calls_used >= state.budget.max_tool_calls:
            raise PolicyError("Tool-call budget exhausted")

    if isinstance(action, EvidenceRequest):
        gap = gaps_by_id.get(action.gap_id)
        if gap is None:
            raise PolicyError(f"Unknown evidence gap: {action.gap_id}")
        if gap.status not in {"open", "querying", "evidence_collected", "partially_resolved"}:
            raise PolicyError(f"Evidence gap {action.gap_id} is already {gap.status}")
        tool = registry.get(action.tool_name)
        collected_types = {e.evidence_type for e in state.evidence if e.status.value == "available"}
        missing_gap_types = set(gap.required_evidence_types) - collected_types
        if not (tool.provides_evidence_types & missing_gap_types):
            raise PolicyError(
                f"{action.tool_name} cannot resolve {action.gap_id}; it provides "
                f"{sorted(tool.provides_evidence_types)}"
            )
        allowed_parameters = set(tool.input_schema.get("properties", {}))
        unknown_parameters = set(action.parameters) - allowed_parameters
        if unknown_parameters:
            raise PolicyError(f"Unsupported parameters for {action.tool_name}: {sorted(unknown_parameters)}")
        requested_host = action.parameters.get("host_id")
        if requested_host and requested_host not in state.scope.host_ids:
            raise PolicyError(f"Host {requested_host} is outside the approved scope")
        requested_entities = set(action.parameters.get("entity_ids") or [])
        known_entities = {entity.entity_id for entity in state.entities}
        known_entities |= {ref for evidence in state.evidence for ref in evidence.subject_refs}
        unknown_entities = requested_entities - known_entities
        if unknown_entities:
            raise PolicyError(f"Entities are outside the known case scope: {sorted(unknown_entities)}")
        start = _datetime(action.parameters.get("start_time"))
        end = _datetime(action.parameters.get("end_time"))
        if start and state.scope.start_time and start < state.scope.start_time:
            raise PolicyError("Requested start_time is outside the approved scope")
        if end and state.scope.end_time and end > state.scope.end_time:
            raise PolicyError("Requested end_time is outside the approved scope")
        if start and end and start > end:
            raise PolicyError("start_time must not be after end_time")
        filters = action.parameters.get("filters", {})
        if not isinstance(filters, dict):
            raise PolicyError("filters must be an object")
        limit = action.parameters.get("limit", 1000)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 5000:
            raise PolicyError("limit must be an integer between 1 and 5000")

    if isinstance(action, AnalysisRequest):
        missing_refs = sorted(set(action.evidence_refs) - set(evidence_by_id))
        if missing_refs:
            raise PolicyError(f"Analysis references unknown evidence IDs: {missing_refs}")
        selected_types = {evidence_by_id[ref].evidence_type for ref in action.evidence_refs}
        tool = registry.get(action.tool_name)
        missing_types = sorted(tool.requires_evidence_types - selected_types)
        requirements_met = bool(tool.requires_evidence_types & selected_types) if tool.requirements_mode == "any" else not missing_types
        if not requirements_met:
            raise PolicyError(f"{action.tool_name} requires evidence types: {missing_types}")
        fingerprint = {"evidence_refs": sorted(set(action.evidence_refs))}
        if any(call.tool_name == action.tool_name and call.status == "success" and call.parameters == fingerprint for call in state.tool_calls):
            raise PolicyError(f"Duplicate analysis request for the same evidence: {action.tool_name}")
        matching_obligation = any(
            item.tool_name == action.tool_name
            and item.status == "pending"
            and set(item.evidence_refs) == set(action.evidence_refs)
            for item in state.analysis_obligations
        )
        if not matching_obligation:
            raise PolicyError(f"No pending analysis obligation matches {action.tool_name} and the selected evidence")

    if isinstance(action, ScopeRequest):
        missing_refs = sorted(set(action.reason_evidence_refs) - set(evidence_by_id))
        if missing_refs:
            raise PolicyError(f"Scope request references unknown evidence IDs: {missing_refs}")
        duplicates = sorted(set(action.requested_host_ids) & set(state.scope.host_ids))
        if duplicates:
            raise PolicyError(f"Hosts are already in scope: {duplicates}")
        if state.scope.expansion_policy == "deny":
            raise PolicyError("Scope expansion is disabled by policy")
        if state.budget.scope_expansions_used >= state.budget.max_scope_expansions:
            raise PolicyError("Scope-expansion budget exhausted")
        if len(set(action.requested_host_ids)) > 3:
            raise PolicyError("Scope request is not minimized; at most three candidate hosts are allowed")
        unsupported_domains = set(action.requested_domains) - set(state.scope.allowed_domains)
        if unsupported_domains:
            raise PolicyError(f"Scope request contains disallowed domains: {sorted(unsupported_domains)}")
        supporting = [evidence_by_id[ref] for ref in action.reason_evidence_refs]
        ungrounded_hosts = [host for host in action.requested_host_ids if not any(_contains_host([item.subject_refs, item.data], host) for item in supporting)]
        if ungrounded_hosts:
            raise PolicyError(f"Scope request hosts are not grounded in cited evidence: {sorted(ungrounded_hosts)}")
        if action.start_time and state.scope.start_time and action.start_time < state.scope.start_time:
            raise PolicyError("Scope request start_time exceeds the approved case window")
        if action.end_time and state.scope.end_time and action.end_time > state.scope.end_time:
            raise PolicyError("Scope request end_time exceeds the approved case window")

    if isinstance(action, FinishRequest):
        pending = [
            item.obligation_id for item in state.analysis_obligations
            if item.required_for_closure and item.status in {"pending", "running"}
        ]
        if pending:
            raise PolicyError(f"Finish denied; required analysis obligations remain: {sorted(pending)}")
        untouched = [gap.gap_id for gap in state.evidence_gaps if gap.required_for_closure and gap.status in {"open", "querying"}]
        if untouched:
            raise PolicyError(f"Finish denied; mandatory evidence gaps were not attempted: {sorted(untouched)}")
        analyzing_gaps = [
            gap.gap_id for gap in state.evidence_gaps
            if gap.required_for_closure and gap.status in {"evidence_collected", "analyzing"}
        ]
        if analyzing_gaps:
            raise PolicyError(f"Finish denied; evidence gaps still require analysis: {sorted(analyzing_gaps)}")
        known_gap_ids = set(gaps_by_id)
        declared = set(action.resolved_gap_ids) | set(action.unresolved_gap_ids)
        unknown = declared - known_gap_ids
        if unknown:
            raise PolicyError(f"Finish request references unknown gaps: {sorted(unknown)}")
        if declared != known_gap_ids:
            raise PolicyError(f"Finish request must account for every evidence gap; missing {sorted(known_gap_ids - declared)}")
        actually_resolved = {gap.gap_id for gap in state.evidence_gaps if gap.status == "resolved"}
        falsely_resolved = set(action.resolved_gap_ids) - actually_resolved
        if falsely_resolved:
            raise PolicyError(f"Gaps are not resolved: {sorted(falsely_resolved)}")
