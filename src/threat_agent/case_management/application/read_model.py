from __future__ import annotations

from ...contracts import CaseReadModel, JudgmentResult, ResponsePlan
from ...judgment.domain.models import InvestigationState
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
        tool_calls=_dump(state.tool_calls),
        scope=state.scope.model_dump(mode="json"),
        investigation_timeline=timeline,
        approval_status=approval_status,
        limitations=list(judgment.limitations if judgment else []),
    )
