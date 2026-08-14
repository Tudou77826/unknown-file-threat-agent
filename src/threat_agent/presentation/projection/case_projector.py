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
        "tool_calls": read_model.tool_calls,
        "scope": read_model.scope,
        "scope_expansions": read_model.scope_expansions,
        "approval_status": read_model.approval_status,
        "investigation_timeline": read_model.investigation_timeline,
        "analysis_notes": read_model.analysis_notes,
        "limitations": read_model.limitations,
    }
