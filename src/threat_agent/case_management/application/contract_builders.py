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
    # Online path records evidence in the tool ledger (new activity model);
    # offline deterministic path records it in facts/findings/relations.
    # Harvest from both so the handoff never ships an empty evidence set.
    evidence_refs = sorted(
        {
            ref.evidence_id
            for result in state.tool_ledger.query_results
            for ref in result.evidence_references
        }
        | {
            ref
            for item in [*state.facts, *state.findings, *state.relations]
            for ref in item.evidence_refs
        }
    )
    return JudgmentResult(
        tenant_id=tenant_id,
        case_id=state.case_id,
        source_identity=source_identity,
        verdict=state.verdict,
        facts=state.facts,
        findings=state.findings,
        relations=state.relations,
        evidence_refs=evidence_refs,
        asserted_host_refs=list(state.scope.host_ids),
        coverage=state.coverage,
        active_scenarios=state.active_scenarios,
        limitations=list(state.verdict.limitations),
    )
