from __future__ import annotations

from ...contracts import CaseReadModel, JudgmentResult, ResponsePlan
from ...judgment.domain.models import InvestigationState
from ...judgment.domain.verdict import build_attack_path
from .contract_builders import build_judgment_result


def _dump(items) -> list[dict]:
    return [item.model_dump(mode="json") for item in items]


def build_case_read_model(
    state: InvestigationState,
    *,
    tenant_id: str = "default",
    lifecycle_status: str | None = None,
    judgment: JudgmentResult | None = None,
    response_plan: ResponsePlan | None = None,
    approval_status: str | None = None,
) -> CaseReadModel:
    """Commit internal case state into the stable presentation contract."""

    if judgment is None and state.verdict is not None:
        judgment = build_judgment_result(state, tenant_id=tenant_id)
    notes = list(
        dict.fromkeys(
            note for obligation in state.analysis_obligations for note in obligation.limitations
        )
    )
    timeline = [
        {
            "sequence": index,
            "event_type": "tool_call",
            "tool_name": call.tool_name,
            "status": call.status,
            "objective": call.objective,
            "error": call.error,
        }
        for index, call in enumerate(state.tool_calls, start=1)
    ]
    return CaseReadModel(
        tenant_id=tenant_id,
        case_id=state.case_id,
        source_identity="case-management/read-model",
        lifecycle_status=lifecycle_status or ("judged" if state.finished else "investigating"),
        judgment=judgment,
        response_plan=response_plan,
        entities=_dump(state.entities),
        evidence=_dump(state.evidence),
        attack_path=build_attack_path(state),
        facts=_dump(state.facts),
        findings=_dump(state.findings),
        hypotheses=_dump(state.hypotheses),
        evidence_roles=_dump(state.evidence_roles),
        coverage=state.coverage,
        analysis_obligations=_dump(state.analysis_obligations),
        evidence_gaps=_dump(state.evidence_gaps),
        tool_calls=_dump(state.tool_calls),
        planner_decisions=_dump(state.planner_decisions),
        tool_scores=_dump(state.tool_scores),
        evidence_packs=_dump(state.evidence_packs),
        repair_actions=_dump(state.repair_actions),
        active_scenarios=list(state.active_scenarios),
        scope=state.scope.model_dump(mode="json"),
        scope_expansions=_dump(state.scope_expansions),
        verdict_validation_errors=list(state.verdict_validation_errors),
        analysis_notes=notes,
        investigation_timeline=timeline,
        approval_status=approval_status,
        limitations=list(judgment.limitations if judgment else []),
    )
