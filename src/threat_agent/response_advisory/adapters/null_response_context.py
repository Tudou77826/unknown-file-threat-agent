from __future__ import annotations

from ...contracts import JudgmentResult, ResponseContext


class NullResponseContextProvider:
    """Explicit fallback until an asset and business context source is configured."""

    def load(self, judgment: JudgmentResult) -> ResponseContext:
        return ResponseContext(
            tenant_id=judgment.tenant_id,
            case_id=judgment.case_id,
            source_identity="response-context:null",
            missing_context=[
                "Asset criticality and business ownership are not configured",
                "Organization response policy and maintenance window are not configured",
            ],
        )
