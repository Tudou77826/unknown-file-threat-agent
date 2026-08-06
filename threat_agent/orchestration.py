from __future__ import annotations

import uuid
from typing import Any

from .models import EvidenceBundle, EvidencePack, EvidenceStatus, InvestigationState, RepairAction, ToolScore


PRIORITY_WEIGHT = {"low": 8.0, "medium": 18.0, "high": 30.0, "critical": 45.0}
ROLE_WEIGHT = {
    "identity": 16.0,
    "execution": 24.0,
    "attribution": 20.0,
    "provenance": 14.0,
    "behavior": 18.0,
    "impact": 22.0,
    "scope": 12.0,
    "counter_evidence": 24.0,
}
DOMAIN_COST = {"process": 2.0, "file": 3.0, "network": 4.0, "persistence": 3.0, "reputation": 2.0}


def score_tool(state: InvestigationState, tool: Any, compatible_gaps: list[Any], matching_roles: list[Any], already_called: bool) -> ToolScore:
    components: dict[str, float] = {}
    rationale: list[str] = []
    components["gap_priority"] = max((PRIORITY_WEIGHT[item.priority] for item in compatible_gaps), default=35.0 if tool.kind == "analysis" else 0.0)
    if components["gap_priority"]:
        rationale.append("Addresses the highest-priority compatible evidence gap")
    components["evidence_role"] = max((ROLE_WEIGHT[item.role_type] for item in matching_roles), default=0.0)
    if matching_roles:
        rationale.append("Matches unsatisfied Evidence Role(s)")
    hypothesis_confidence = max(
        (
            hypothesis.confidence
            for role in matching_roles
            for hypothesis in state.hypotheses
            if hypothesis.hypothesis_id in role.hypothesis_refs
        ),
        default=0.0,
    )
    components["hypothesis_information_gain"] = round(14.0 * hypothesis_confidence, 3)
    missing_types = {
        evidence_type
        for gap in compatible_gaps
        for evidence_type in gap.required_evidence_types
        if evidence_type not in {item.evidence_type for item in state.evidence if item.status == EvidenceStatus.AVAILABLE}
    }
    components["missing_evidence_gain"] = min(16.0, 5.0 * len(tool.provides_evidence_types & missing_types))
    coverage = state.coverage.get(tool.domain)
    if coverage is None:
        components["coverage_expectation"] = 2.0
    elif coverage.status == EvidenceStatus.AVAILABLE and coverage.completeness == "complete":
        components["coverage_expectation"] = 9.0
        rationale.append("The data source has complete Coverage")
    elif coverage.status == EvidenceStatus.PARTIAL:
        components["coverage_expectation"] = -8.0
        rationale.append("Partial Coverage reduces expected information gain")
    elif coverage.status in {EvidenceStatus.UNAVAILABLE, EvidenceStatus.ERROR}:
        components["coverage_expectation"] = -35.0
        rationale.append("The data source is unavailable or in error")
    else:
        components["coverage_expectation"] = -2.0
    components["counter_evidence_value"] = 12.0 if any(item.role_type == "counter_evidence" for item in matching_roles) else 0.0
    if components["counter_evidence_value"]:
        rationale.append("Can test a legitimate competing explanation")
    components["entity_applicability"] = 5.0 if state.scope.entity_ids or state.entities else 0.0
    components["repair_priority"] = 28.0 if any(item.status == "pending" and tool.name in item.recommended_tools for item in state.repair_actions) else 0.0
    if components["repair_priority"]:
        rationale.append("Recommended by a pending RepairAction")
    components["repeat_penalty"] = -24.0 if already_called else 0.0
    components["query_cost"] = -DOMAIN_COST.get(tool.domain, 4.0)
    components["scope_cost"] = -12.0 if tool.name in {"query_hash_presence", "query_remote_login_sessions", "query_account_activity_across_hosts", "query_host_asset_context"} else 0.0
    if tool.kind == "analysis":
        components["deterministic_obligation"] = 30.0
        rationale.append("A deterministic AnalysisObligation is ready")
    score = round(sum(components.values()), 3)
    return ToolScore(
        iteration=state.budget.iterations_used,
        tool_name=tool.name,
        score=score,
        compatible_gap_ids=[item.gap_id for item in compatible_gaps],
        matching_role_ids=[item.role_id for item in matching_roles],
        components=components,
        rationale=rationale,
    )


def build_evidence_pack(state: InvestigationState, call_id: str, tool_name: str, gap_id: str, parameters: dict[str, Any], bundle: EvidenceBundle) -> EvidencePack:
    gap = next(item for item in state.evidence_gaps if item.gap_id == gap_id)
    roles = [
        role for role in state.evidence_roles
        if set(role.required_evidence_types) & set(gap.required_evidence_types)
    ]
    evidence_refs = [item.evidence_id for item in bundle.evidence]
    obligations = [
        item.obligation_id for item in state.analysis_obligations
        if set(item.evidence_refs) & set(evidence_refs)
    ]
    if bundle.status == EvidenceStatus.ERROR:
        outcome = "error"
    elif bundle.status == EvidenceStatus.UNAVAILABLE:
        outcome = "unavailable"
    elif bundle.evidence and bundle.status == EvidenceStatus.PARTIAL:
        outcome = "partial"
    elif bundle.evidence:
        outcome = "positive"
    else:
        outcome = "negative" if bundle.coverage.completeness == "complete" else "partial"
    return EvidencePack(
        pack_id=f"pack-{uuid.uuid4().hex[:12]}",
        request_call_id=call_id,
        tool_name=tool_name,
        target_gap_id=gap_id,
        target_role_ids=[item.role_id for item in roles],
        target_hypothesis_ids=sorted({ref for item in roles for ref in item.hypothesis_refs}),
        query_parameters=parameters,
        requested_host_ids=[str(parameters.get("host_id"))] if parameters.get("host_id") else list(state.scope.host_ids),
        requested_start=bundle.coverage.requested_start,
        requested_end=bundle.coverage.requested_end,
        evidence_refs=evidence_refs,
        returned_evidence_types=sorted({item.evidence_type for item in bundle.evidence}),
        coverage=bundle.coverage,
        analysis_obligation_refs=obligations,
        outcome=outcome,
        limitations=list(dict.fromkeys([*bundle.limitations, *bundle.coverage.limitations])),
    )


def add_repair_action(state: InvestigationState, *, repair_type: str, trigger: str, reason: str, target_gap_id: str | None = None, recommended_tools: list[str] | None = None, reason_evidence_refs: list[str] | None = None, blocking: bool = False) -> RepairAction:
    fingerprint = (repair_type, trigger, target_gap_id, tuple(recommended_tools or []))
    for existing in state.repair_actions:
        if (existing.repair_type, existing.trigger, existing.target_gap_id, tuple(existing.recommended_tools)) == fingerprint and existing.status == "pending":
            return existing
    action = RepairAction(
        repair_id=f"repair-{uuid.uuid4().hex[:12]}",
        repair_type=repair_type,
        trigger=trigger,
        target_gap_id=target_gap_id,
        recommended_tools=list(recommended_tools or []),
        reason_evidence_refs=list(reason_evidence_refs or []),
        reason=reason,
        blocking=blocking,
    )
    state.repair_actions.append(action)
    return action


def plan_verdict_repairs(state: InvestigationState, errors: list[str]) -> list[RepairAction]:
    if not errors or state.budget.verdict_repairs_used >= state.budget.max_verdict_repairs:
        return []
    threat_type = state.verdict.threat_type if state.verdict else "unknown"
    preferred_gap_types = {
        "data_exfiltration": ["transfer_counter", "exfiltration", "data_transfer"],
        "ransomware": ["ransomware_counter", "ransomware_chain", "file_encryption"],
        "backdoor_c2": ["remote_command", "persistence", "counter_evidence"],
    }.get(threat_type, [])
    attempted = {item.tool_name for item in state.tool_calls if item.status not in {"denied", "error"}}
    repairs: list[RepairAction] = []
    for gap_type in preferred_gap_types:
        gap = next((item for item in state.evidence_gaps if item.gap_type == gap_type), None)
        if gap is None:
            continue
        remaining = [tool for tool in gap.recommended_tools if tool not in attempted]
        if not remaining:
            continue
        repairs.append(add_repair_action(
            state,
            repair_type="repair_verdict_support",
            trigger="verdict_validation_failed",
            target_gap_id=gap.gap_id,
            recommended_tools=remaining,
            reason="; ".join(errors),
            blocking=True,
        ))
        break
    return repairs


def apply_pending_repair(
    state: InvestigationState,
    repair_ids: set[str] | None = None,
) -> RepairAction | None:
    if state.budget.repair_actions_used >= state.budget.max_repair_actions:
        return None
    action = next(
        (
            item
            for item in state.repair_actions
            if item.status == "pending"
            and item.attempts < item.max_attempts
            and (repair_ids is None or item.repair_id in repair_ids)
        ),
        None,
    )
    if action is None:
        return None
    action.attempts += 1
    state.budget.repair_actions_used += 1
    gap = next((item for item in state.evidence_gaps if item.gap_id == action.target_gap_id), None)
    attempted = {item.tool_name for item in state.tool_calls if item.status not in {"denied", "error"}}
    available = [tool for tool in action.recommended_tools if tool not in attempted]
    if gap and available:
        gap.status = "open"
        gap.resolution = "none"
        gap.resolution_refs = []
        gap.limitations.append(f"Reopened by {action.repair_id}: {action.reason}")
        action.status = "applied"
    else:
        action.status = "exhausted"
        action.limitations.append("No unattempted compatible repair tool remains")
    return action
