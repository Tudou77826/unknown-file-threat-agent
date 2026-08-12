from __future__ import annotations

import json
from typing import Any, Protocol

from langchain_core.exceptions import OutputParserException
from pydantic import ValidationError

from ...contracts import JudgmentResult, KnowledgeResult, ResponseAction, ResponseContext
from ..domain.models import ResponseProposal


class ResponsePlanner(Protocol):
    def propose(
        self,
        judgment: JudgmentResult,
        knowledge: list[KnowledgeResult],
        validation_errors: list[str],
        response_context: ResponseContext | None = None,
    ) -> ResponseProposal: ...


class DeterministicResponsePlanner:
    """Offline response policy used for repeatable tests and demonstrations."""

    def propose(
        self,
        judgment: JudgmentResult,
        knowledge: list[KnowledgeResult],
        validation_errors: list[str],
        response_context: ResponseContext | None = None,
    ) -> ResponseProposal:
        finding_refs = [item.finding_id for item in judgment.findings]
        fact_refs = [item.fact_id for item in judgment.facts]
        refs = (finding_refs or fact_refs or judgment.evidence_refs)[:8]
        target_refs = sorted(
            {
                ref
                for item in [*judgment.facts, *judgment.findings]
                for ref in item.subject_refs
            }
        )[:8]
        level = judgment.verdict.level.value
        assets = list((response_context.asset_context if response_context else {}).get("assets", []))
        asset = assets[0] if assets else {}
        isolation_policy = asset.get("isolation_policy")
        approval_class = {
            "allowed": "security_lead",
            "security_approval": "security_lead",
            "dual_approval": "business_owner",
            "prohibited": "business_owner",
        }.get(isolation_policy, "security_lead")
        business_precondition = (
            f"Follow {asset.get('isolation_policy')} isolation policy for "
            f"{asset.get('asset_name')} during {asset.get('maintenance_window')}"
            if asset
            else "Confirm business owner and approved maintenance path"
        )
        isolation_impact = asset.get(
            "isolation_impact", "Network access for the affected host may be interrupted"
        )
        if level in {"confirmed_malicious", "likely_malicious", "suspicious"}:
            actions = [
                ResponseAction(
                    action_id="response-isolate-001",
                    action_type="isolate_host",
                    target_refs=target_refs,
                    rationale="Contain observed malicious or suspicious activity while preserving evidence",
                    judgment_refs=refs,
                    preconditions=[
                        "Confirm target asset identity",
                        business_precondition,
                        "Preserve volatile and relevant forensic evidence",
                    ],
                    expected_impact=isolation_impact,
                    approval_class=approval_class,
                    rollback_steps=["Remove isolation after validation and owner approval"],
                    verification_steps=[
                        "Verify the host can no longer reach unapproved endpoints",
                        "Monitor for activity from related identities or hosts",
                    ],
                ),
                ResponseAction(
                    action_id="response-preserve-001",
                    action_type="preserve_evidence",
                    target_refs=target_refs,
                    rationale="Retain evidence required for validation and follow-up investigation",
                    judgment_refs=refs,
                    preconditions=["Confirm evidence storage destination and retention policy"],
                    expected_impact="Additional storage and collection load",
                    approval_class="operator",
                    rollback_steps=["Stop collection after retention requirements are met"],
                    verification_steps=["Verify evidence hashes and custody metadata"],
                ),
            ]
            residual = ["Related hosts or identities may remain outside the current investigation scope"]
        elif level in {"benign", "likely_benign"}:
            actions = [
                ResponseAction(
                    action_id="response-monitor-001",
                    action_type="monitor_case",
                    target_refs=target_refs,
                    rationale="Maintain observation without disruptive containment",
                    judgment_refs=refs,
                    preconditions=["Retain the judgment evidence and limitations"],
                    expected_impact="No direct service interruption",
                    approval_class="none",
                    rollback_steps=[],
                    verification_steps=["Reopen the case if contradictory telemetry appears"],
                )
            ]
            residual = ["The conclusion remains bounded by recorded telemetry coverage"]
        else:
            actions = [
                ResponseAction(
                    action_id="response-collect-001",
                    action_type="collect_additional_evidence",
                    target_refs=target_refs,
                    rationale="Reduce uncertainty before disruptive containment",
                    judgment_refs=refs,
                    preconditions=["Confirm data source availability and investigation scope"],
                    expected_impact="Additional telemetry collection load",
                    approval_class="operator",
                    rollback_steps=["Stop collection when the approved budget is exhausted"],
                    verification_steps=["Confirm new evidence has explicit Coverage metadata"],
                )
            ]
            residual = ["Threat status remains uncertain until evidence gaps are resolved"]
        missing = []
        if any(item.status == "not_configured" for item in knowledge):
            missing.append("Organization response SOP and approval knowledge are not configured")
        if response_context is not None:
            missing.extend(response_context.missing_context)
        return ResponseProposal(
            actions=actions,
            missing_context=missing,
            residual_risk=residual,
        )


class StructuredResponsePlanner:
    """Use a chat model's structured-output capability for response planning."""

    def __init__(self, model: Any):
        self.model = model
        self.structured_model = model.with_structured_output(
            ResponseProposal, method="json_mode"
        )

    def propose(
        self,
        judgment: JudgmentResult,
        knowledge: list[KnowledgeResult],
        validation_errors: list[str],
        response_context: ResponseContext | None = None,
    ) -> ResponseProposal:
        payload = {
            "judgment": judgment.model_dump(mode="json"),
            "knowledge": [item.model_dump(mode="json") for item in knowledge],
            "validation_errors": validation_errors,
            "response_context": (
                response_context.model_dump(mode="json") if response_context else None
            ),
        }
        messages = [
            {
                "role": "system",
                "content": (
                    "Return one JSON object matching the ResponseProposal schema. "
                    "The top-level keys are actions, missing_context and residual_risk; "
                    "do not wrap the object in ResponsePlan or add contract metadata. "
                    "Return no more than three actions. "
                    "Write all natural-language fields in Simplified Chinese. "
                    "Create a response advisory plan. Judgment facts are read-only. "
                    "Every action must include rationale, preconditions, expected impact, "
                    "approval class, rollback steps, verification steps, and resolvable "
                    "judgment references. approval_class must be exactly one of none, "
                    "operator, security_lead, business_owner. Never claim that an action "
                    "was executed. JSON schema: "
                    + json.dumps(ResponseProposal.model_json_schema(), ensure_ascii=False)
                ),
            },
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ]
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                response = self.structured_model.invoke(messages)
                return ResponseProposal.model_validate(response)
            except (OutputParserException, ValidationError) as error:
                last_error = error
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "The previous JSON did not match ResponseProposal. Return only a "
                            "corrected JSON object with the exact schema and enum values. "
                            f"Validation error: {str(error)[:1200]}"
                        ),
                    }
                )
        raise RuntimeError("Response model could not produce a valid structured proposal") from last_error
