from __future__ import annotations

import uuid

from .models import AnalysisRequest, Entity, EvidenceBundle, EvidenceRequest, FactFindingBundle, FinishRequest, InvestigationState, ScopeExpansion, ScopeRequest, ToolCall, ToolScore
from .planner import Planner
from .policy import PolicyError, validate_action
from .state import apply_analysis_bundle, apply_evidence_bundle
from .tools import ToolRegistry
from .verdict import evaluate_verdict, validate_verdict
from .orchestration import add_repair_action, apply_pending_repair, build_evidence_pack, plan_verdict_repairs


class InvestigationEngine:
    def __init__(self, registry: ToolRegistry, planner: Planner):
        self.registry = registry
        self.planner = planner

    def run(self, state: InvestigationState) -> InvestigationState:
        while not state.finished:
            state.budget.iterations_used += 1
            if state.budget.max_iterations - state.budget.iterations_used <= 3 and not any(item.repair_type == "converge_under_budget" for item in state.repair_actions):
                repair = add_repair_action(state, repair_type="converge_under_budget", trigger="budget_near_exhaustion", reason="Prioritize mandatory unresolved gaps and avoid optional low-information queries", blocking=False)
                repair.status = "applied"
            catalog_snapshot = self.registry.catalog(state)
            state.tool_scores.extend(
                ToolScore.model_validate(item["score_breakdown"])
                for item in catalog_snapshot
                if not any(existing.iteration == state.budget.iterations_used and existing.tool_name == item["tool_name"] for existing in state.tool_scores)
            )
            if state.budget.iterations_used > state.budget.max_iterations:
                state.verdict = evaluate_verdict(state)
                state.verdict.limitations.append("Investigation stopped because the iteration budget was exhausted")
                state.finished = True
                break
            action = self.planner.plan(state)
            try:
                validate_action(action, state, self.registry)
            except (PolicyError, KeyError) as first_error:
                repair_record = add_repair_action(
                    state,
                    repair_type="repair_invalid_action",
                    trigger="policy_validation_failed",
                    target_gap_id=getattr(action, "gap_id", None),
                    recommended_tools=[],
                    reason=str(first_error),
                    blocking=True,
                )
                repair = getattr(self.planner, "repair", None)
                if repair is not None:
                    try:
                        action = repair(state, action, str(first_error))
                        validate_action(action, state, self.registry)
                        repair_record.status = "applied"
                        repair_record.attempts = 1
                    except Exception as repair_error:
                        self._record_denied(state, action, f"Repair failed: {type(repair_error).__name__}: {repair_error}")
                        continue
                else:
                    self._record_denied(state, action, str(first_error))
                    self._fail_matching_obligations(state, action, str(first_error))
                    continue

            if isinstance(action, FinishRequest):
                state.verdict = evaluate_verdict(state)
                errors = validate_verdict(state, state.verdict)
                state.verdict_validation_errors = list(errors)
                if errors:
                    repairs = plan_verdict_repairs(state, errors)
                    applied = apply_pending_repair(
                        state,
                        {item.repair_id for item in repairs},
                    ) if repairs else None
                    if applied and applied.status == "applied":
                        state.budget.verdict_repairs_used += 1
                        state.verdict = None
                        state.verdict_validation_errors = []
                        continue
                    state.verdict.limitations.extend(errors)
                    state.verdict.level = "insufficient_evidence"
                state.finished = True
                break
            if isinstance(action, ScopeRequest):
                approved = state.scope.expansion_policy == "automatic"
                expansion = ScopeExpansion(
                    expansion_id=f"scope-{uuid.uuid4().hex[:10]}",
                    candidate_host_ids=list(dict.fromkeys(action.requested_host_ids)),
                    reason_type=action.reason_type,
                    reason_evidence_refs=action.reason_evidence_refs,
                    requested_domains=action.requested_domains,
                    start_time=action.start_time,
                    end_time=action.end_time,
                    approval_status="approved" if approved else "pending",
                    approval_source="policy:auto" if approved else "human_approval_required",
                    limitations=[] if approved else ["Scope was not expanded because explicit approval is required"],
                )
                state.scope_expansions.append(expansion)
                if approved:
                    for host_id in expansion.candidate_host_ids:
                        if host_id not in state.scope.host_ids:
                            state.scope.host_ids.append(host_id)
                        entity_id = f"host:{host_id}"
                        if not any(item.entity_id == entity_id for item in state.entities):
                            state.entities.append(Entity(entity_id=entity_id, entity_type="host", attributes={"scope_expansion": expansion.expansion_id}))
                    state.budget.scope_expansions_used += 1
                else:
                    for gap in state.evidence_gaps:
                        if gap.gap_type in {"cross_host_confirmation", "cross_host_counter"}:
                            gap.status = "unresolvable"
                            gap.resolution = "unresolvable"
                            gap.limitations.append("Candidate host was not added because scope approval is required")
                        elif gap.gap_type == "cross_host_lead":
                            gap.status = "resolved"
                            gap.resolution = "positive"
                            gap.resolution_refs = list(action.reason_evidence_refs)
                    repair = add_repair_action(
                        state,
                        repair_type="respect_scope_denial",
                        trigger="scope_approval_required",
                        reason="Do not query target-host evidence until explicit approval is recorded",
                        reason_evidence_refs=action.reason_evidence_refs,
                        blocking=False,
                    )
                    repair.status = "applied"
                state.tool_calls.append(ToolCall(
                    call_id=f"call-{uuid.uuid4().hex[:10]}",
                    tool_name="scope_request",
                    action_type=action.action_type,
                    status="success" if approved else "denied",
                    objective=action.objective,
                    parameters={
                        "requested_host_ids": action.requested_host_ids,
                        "reason_evidence_refs": action.reason_evidence_refs,
                        "reason_type": action.reason_type,
                        "requested_domains": action.requested_domains,
                    },
                    error=None if approved else "Scope expansion requires explicit human approval",
                ))
                continue
            call_parameters = (
                {"evidence_refs": sorted(set(action.evidence_refs))}
                if isinstance(action, AnalysisRequest)
                else {"gap_id": action.gap_id, **action.parameters}
            )
            call = ToolCall(call_id=f"call-{uuid.uuid4().hex[:10]}", tool_name=action.tool_name, action_type=action.action_type, status="success", objective=action.objective, parameters=call_parameters)
            matching_obligations = []
            if isinstance(action, AnalysisRequest):
                matching_obligations = [
                    item for item in state.analysis_obligations
                    if item.tool_name == action.tool_name
                    and item.status == "pending"
                    and set(item.evidence_refs) == set(action.evidence_refs)
                ]
                for obligation in matching_obligations:
                    obligation.status = "running"
                    for gap in state.evidence_gaps:
                        if gap.gap_id in obligation.gap_ids:
                            gap.status = "analyzing"
            try:
                invocation_parameters = (
                    action.parameters
                    if isinstance(action, EvidenceRequest)
                    else {"evidence_refs": sorted(set(action.evidence_refs))}
                )
                result = self.registry.invoke(action.tool_name, state, invocation_parameters)
                state.budget.tool_calls_used += 1
                if isinstance(result, EvidenceBundle):
                    requested_types = self.registry.get(action.tool_name).provides_evidence_types
                    apply_evidence_bundle(state, result, self.registry, requested_types)
                    state.evidence_packs.append(build_evidence_pack(
                        state,
                        call.call_id,
                        action.tool_name,
                        action.gap_id,
                        action.parameters,
                        result,
                    ))
                    if not result.evidence and result.coverage.completeness != "complete":
                        gap = next(item for item in state.evidence_gaps if item.gap_id == action.gap_id)
                        remaining = [name for name in gap.recommended_tools if not any(item.tool_name == name for item in state.tool_calls)]
                        if remaining:
                            add_repair_action(
                                state,
                                repair_type="use_alternative_source",
                                trigger="empty_result_with_incomplete_coverage",
                                target_gap_id=gap.gap_id,
                                recommended_tools=remaining,
                                reason="The query returned no evidence, but Coverage is not complete; absence cannot be concluded",
                            )
                    for repair_action in state.repair_actions:
                        if repair_action.status == "pending" and action.tool_name in repair_action.recommended_tools:
                            repair_action.status = "applied"
                            repair_action.attempts += 1
                            state.budget.repair_actions_used += 1
                    call.status = result.status.value if result.status.value in {"empty", "partial", "unavailable", "error"} else "success"
                elif isinstance(result, FactFindingBundle):
                    apply_analysis_bundle(state, result, action.tool_name, action.evidence_refs)
            except (PolicyError, KeyError) as exc:
                call.status, call.error = "denied", str(exc)
            except Exception as exc:
                call.status, call.error = "error", f"{type(exc).__name__}: {exc}"
                add_repair_action(state, repair_type="complete_analyzer_inputs" if isinstance(action, AnalysisRequest) else "use_alternative_source", trigger="tool_execution_failed", target_gap_id=getattr(action, "gap_id", None), reason=call.error, blocking=isinstance(action, AnalysisRequest))
            if call.status in {"denied", "error"}:
                for obligation in matching_obligations:
                    obligation.status = "failed"
                    obligation.limitations.append(call.error or "Analysis execution failed")
                    for gap in state.evidence_gaps:
                        if gap.gap_id in obligation.gap_ids:
                            gap.status = "partially_resolved"
            state.tool_calls.append(call)
            self._resolve_exhausted_alternative_gaps(state)
            if state.budget.iterations_used >= state.budget.max_iterations:
                state.verdict = evaluate_verdict(state)
                state.verdict.limitations.append("Investigation stopped because the iteration budget was exhausted")
                state.finished = True
        return state

    @staticmethod
    def _record_denied(state: InvestigationState, action, error: str) -> None:
        state.tool_calls.append(ToolCall(
            call_id=f"call-{uuid.uuid4().hex[:10]}",
            tool_name=getattr(action, "tool_name", None) or action.action_type,
            action_type=action.action_type,
            status="denied",
            objective=action.objective,
            parameters=action.model_dump(mode="json", exclude={"action_type", "tool_name", "objective"}),
            error=error,
        ))

    @staticmethod
    def _fail_matching_obligations(state: InvestigationState, action, error: str) -> None:
        if not isinstance(action, AnalysisRequest):
            return
        selected = set(action.evidence_refs)
        for obligation in state.analysis_obligations:
            if obligation.status == "pending" and obligation.tool_name == action.tool_name and set(obligation.evidence_refs) == selected:
                obligation.status = "failed"
                obligation.limitations.append(error)

    def _resolve_exhausted_alternative_gaps(self, state: InvestigationState) -> None:
        attempted = {call.tool_name for call in state.tool_calls if call.status not in {"denied", "error"}}
        available_types = {item.evidence_type for item in state.evidence if item.status.value == "available"}
        for gap in state.evidence_gaps:
            if gap.requirement_mode != "any" or gap.status != "partially_resolved":
                continue
            relevant_tools = [name for name in gap.recommended_tools if name in {item.name for item in self.registry.list()}]
            if relevant_tools and set(relevant_tools) <= attempted and not (set(gap.required_evidence_types) & available_types):
                gap.status = "resolved"
                gap.resolution = "negative"
