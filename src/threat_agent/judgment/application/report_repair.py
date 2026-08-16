"""Constrained rejudgment loop for report grounding failures (Feature 14).

The coordinator never repairs citations locally: when validation fails, the
composer LLM rejudges the affected semantic units against the authorized
evidence whitelist and may change the conclusion. Model failures, timeouts and
format errors all funnel into the same budget and lead to the deterministic
fallback path.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from ..domain.models import InvestigationState
from .report_validation import ReportGroundingValidator, ReportValidationIssue
from .reporting import ReportDraft, StructuredReportComposer

EventSink = Callable[[str, str, dict | None], None]


@dataclass
class RepairOutcome:
    draft: ReportDraft
    issues: list[ReportValidationIssue]
    rejudgments_used: int
    # True when the loop ended because the budget ran out or the model failed,
    # as opposed to ending with a clean draft.
    exhausted: bool


class ReportRepairCoordinator:
    def __init__(
        self,
        composer: StructuredReportComposer,
        validator: ReportGroundingValidator | None = None,
        *,
        event_sink: EventSink | None = None,
    ):
        self.composer = composer
        self.validator = validator or ReportGroundingValidator()
        self.event_sink = event_sink or (lambda _kind, _message, _details=None: None)

    def evaluate(
        self,
        state: InvestigationState,
        draft: ReportDraft,
        *,
        max_rejudgments: int,
    ) -> RepairOutcome:
        issues = self.validator.validate(state, draft)
        self._emit_validation(issues, attempt=0)
        attempts = 0
        while issues and attempts < max_rejudgments:
            attempts += 1
            previous_codes = sorted({issue.code for issue in issues})
            started = time.perf_counter()
            try:
                draft = self.composer.rejudge(state, draft, issues, attempt=attempts)
            except Exception as error:
                # Model failure, timeout and format errors share one path: the
                # budget is consumed and the fallback report is published.
                self.event_sink("repair", "报告重新研判失败，转入兜底发布", {
                    "node": "gate",
                    "attempt": attempts,
                    "error_type": type(error).__name__,
                    "error_message": str(error)[:500],
                    "issue_codes": previous_codes,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                })
                return RepairOutcome(draft, issues, attempts, exhausted=True)
            duration_ms = round((time.perf_counter() - started) * 1000, 3)
            issues = self.validator.validate(state, draft)
            self.event_sink("repair", f"第 {attempts} 次报告重新研判完成", {
                "node": "gate",
                "attempt": attempts,
                "previous_issue_codes": previous_codes,
                "issue_codes": sorted({issue.code for issue in issues}),
                "issue_locations": [issue.location for issue in issues],
                "duration_ms": duration_ms,
            })
        exhausted = bool(issues)
        return RepairOutcome(draft, issues, attempts, exhausted)

    def _emit_validation(self, issues: list[ReportValidationIssue], *, attempt: int) -> None:
        self.event_sink("validation", "报告发布接地校验完成", {
            "node": "gate",
            "attempt": attempt,
            "passed": not issues,
            "issue_codes": sorted({issue.code for issue in issues}),
            "issue_locations": [issue.location for issue in issues],
        })
