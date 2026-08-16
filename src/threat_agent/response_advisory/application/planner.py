from __future__ import annotations

import json
from typing import Any, Callable, Protocol

from ...contracts import JudgmentResult, KnowledgeResult, ResponseContext
from ...shared.llm import invoke_llm
from ..domain.models import ResponseProposal


class ResponsePlanner(Protocol):
    def propose(
        self,
        judgment: JudgmentResult,
        knowledge: list[KnowledgeResult],
        validation_errors: list[str],
        response_context: ResponseContext | None = None,
    ) -> ResponseProposal: ...


class StructuredResponsePlanner:
    """Use a chat model's structured-output capability for response planning."""

    def __init__(self, model: Any, event_sink: Callable | None = None):
        self.model = model
        self.event_sink = event_sink or (lambda _kind, _message, _details=None: None)
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
                    "was executed. "
                    "If judgment.publication_status is 'fallback', the verdict did not "
                    "survive grounding validation: only propose re-analysis, additional "
                    "data collection or manual review, and never isolation, blocking, "
                    "quarantine or deletion. "
                    "JSON schema: "
                    + json.dumps(ResponseProposal.model_json_schema(), ensure_ascii=False)
                ),
            },
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ]

        def invoke_once() -> ResponseProposal:
            return ResponseProposal.model_validate(self.structured_model.invoke(messages))

        def build_feedback(_attempt: int, error: Exception):
            return {
                "role": "user",
                "content": (
                    "The previous JSON did not match ResponseProposal. Return only a "
                    "corrected JSON object with the exact schema and enum values. "
                    f"Validation error: {str(error)[:1200]}"
                ),
            }

        def on_attempt(attempt: int) -> None:
            self.event_sink("model_input", "处置建议模型输入", {
                "phase": "response_advisory",
                "attempt": attempt,
                "messages": messages,
            })

        def on_output(_attempt: int, output: ResponseProposal) -> None:
            self.event_sink("model_output", "处置建议模型输出", {
                "phase": "response_advisory",
                "output": output.model_dump(mode="json"),
            })

        def on_failure(attempt: int, error: Exception, kind: str) -> None:
            self.event_sink(
                "model_output",
                "处置建议模型输出校验失败" if kind == "parse" else "处置建议模型调用失败",
                {
                    "phase": "response_advisory",
                    "attempt": attempt,
                    "error_type": type(error).__name__,
                    "error_message": str(error),
                },
            )

        return invoke_llm(
            invoke_once,
            messages=messages,
            build_feedback=build_feedback,
            on_attempt=on_attempt,
            on_output=on_output,
            on_failure=on_failure,
            parse_max_attempts=3,
        )
