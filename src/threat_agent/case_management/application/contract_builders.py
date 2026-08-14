from __future__ import annotations

from ...contracts import JudgmentResult
from ...judgment.domain.models import InvestigationState


def build_judgment_result(
    state: InvestigationState,
    *,
    tenant_id: str = "default",
    source_identity: str = "judgment-engine",
) -> JudgmentResult:
    if state.verdict is None:
        raise ValueError("A published JudgmentResult requires a verdict")
    evidence_refs = sorted(
        {
            ref.evidence_id
            for result in state.tool_ledger.query_results
            for ref in result.evidence_references
        }
    )
    return JudgmentResult(
        tenant_id=tenant_id,
        case_id=state.case_id,
        source_identity=source_identity,
        verdict=state.verdict,
        evidence_refs=evidence_refs,
        asserted_host_refs=list(state.scope.host_ids),
        limitations=list(state.verdict.limitations),
    )
