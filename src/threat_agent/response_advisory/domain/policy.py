from __future__ import annotations

from ...contracts import JudgmentResult
from .models import ResponseProposal


# A fallback publication carries no safety assertions, so it may only justify
# advisory follow-up: re-analysis, more data, or human review. This is an
# allowlist, not a blocklist: action_type is a free-form string, so novel
# spellings of high-impact actions (e.g. delete_file) must fail closed.
FALLBACK_ALLOWED_ACTIONS = {
    "re_run_analysis",
    "collect_more_data",
    "manual_review",
}


def validate_response_proposal(
    judgment: JudgmentResult,
    proposal: ResponseProposal,
) -> list[str]:
    errors: list[str] = []
    if not proposal.actions:
        errors.append("Response proposal contains no candidate actions")
    # The judgment exposes two vocabularies for the same underlying objects:
    # evidence-reference digests and the verdict's own cited activity refs.
    # Both are legitimate judgment references — the report pipeline and the
    # verdict cite activity ids, so accepting only digests made validation
    # fail on correctly-grounded proposals.
    valid_refs = set(judgment.evidence_refs)
    valid_refs |= set(judgment.verdict.supporting_refs)
    valid_refs |= set(judgment.verdict.contradicting_refs)
    action_ids: set[str] = set()
    fallback = judgment.publication_status == "fallback"
    for action in proposal.actions:
        if action.action_id in action_ids:
            errors.append(f"Duplicate response action ID: {action.action_id}")
        action_ids.add(action.action_id)
        unknown = sorted(set(action.judgment_refs) - valid_refs)
        if unknown:
            errors.append(f"Action {action.action_id} cites unknown judgment refs: {unknown}")
        if not action.judgment_refs:
            errors.append(f"Action {action.action_id} has no judgment basis")
        if not action.preconditions:
            errors.append(f"Action {action.action_id} has no preconditions")
        if not action.verification_steps:
            errors.append(f"Action {action.action_id} has no verification steps")
        if fallback and action.action_type not in FALLBACK_ALLOWED_ACTIONS:
            errors.append(
                f"Fallback publication only permits review actions "
                f"(re_run_analysis/collect_more_data/manual_review); "
                f"{action.action_id} requested {action.action_type}"
            )
        # Vocabulary-free self-consistency floor: an action the model itself
        # declares as needing approval must also explain how to roll it back.
        # (Action naming is free-form by design — high-impact discipline is
        # taught through few-shot examples instead of an enum gate.)
        if action.approval_class != "none" and not action.rollback_steps:
            errors.append(
                f"Action {action.action_id} requires approval but has no rollback steps"
            )
    return errors
