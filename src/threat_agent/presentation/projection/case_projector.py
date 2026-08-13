from __future__ import annotations

from ...contracts import CaseReadModel


def case_read_payload(read_model: CaseReadModel) -> dict:
    verdict = (
        read_model.judgment.verdict.model_dump(mode="json")
        if read_model.judgment is not None
        else None
    )
    return {
        "schema_version": read_model.schema_version,
        "tenant_id": read_model.tenant_id,
        "case_id": read_model.case_id,
        "lifecycle_status": read_model.lifecycle_status,
        "verdict": verdict,
        "response_plan": (
            read_model.response_plan.model_dump(mode="json")
            if read_model.response_plan is not None
            else None
        ),
        "entities": read_model.entities,
        "evidence": read_model.evidence,
        "attack_path": read_model.attack_path,
        "facts": read_model.facts,
        "findings": read_model.findings,
        "hypotheses": read_model.hypotheses,
        "evidence_roles": read_model.evidence_roles,
        "coverage": {
            name: value.model_dump(mode="json") for name, value in read_model.coverage.items()
        },
        "analysis_obligations": read_model.analysis_obligations,
        "evidence_gaps": read_model.evidence_gaps,
        "unresolved_gaps": [
            item for item in read_model.evidence_gaps if item.get("status") != "resolved"
        ],
        "tool_calls": read_model.tool_calls,
        "planner_decisions": read_model.planner_decisions,
        "tool_scores": read_model.tool_scores,
        "evidence_packs": read_model.evidence_packs,
        "repair_actions": read_model.repair_actions,
        "active_scenarios": read_model.active_scenarios,
        "scope": read_model.scope,
        "scope_expansions": read_model.scope_expansions,
        "approval_status": read_model.approval_status,
        "investigation_timeline": read_model.investigation_timeline,
        "verdict_validation": {
            "status": "PASS" if not read_model.verdict_validation_errors else "FAIL",
            "errors": read_model.verdict_validation_errors,
        },
        "analysis_notes": read_model.analysis_notes,
        "limitations": read_model.limitations,
    }
