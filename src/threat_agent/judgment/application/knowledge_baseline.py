"""Mandatory knowledge baseline for the investigation runtime (design §5/§6).

After the evidence package is assembled and before the verdict is composed,
one fixed node consults analyst experience plus ATT&CK knowledge. The query
is built from verified behaviors only — no case narrative, no raw file
content. The consultation is recorded in the tool ledger (record-only, never
blocking); any failure surfaces as an explicit degraded/error record while
the investigation continues on security telemetry alone.
"""

from __future__ import annotations

from ...contracts import (
    KnowledgeConsultation,
    KnowledgeConsultationContext,
    KnowledgeConsultationResult,
    KnowledgeConsultationRecord,
    KnowledgeItem,
)
from ...contracts.investigation_tools import InvestigationToolLedger
from ..domain.models import InvestigationState

# How many verified-behavior briefs enter the baseline query (minimization).
_MAX_BEHAVIOR_BRIEFS = 12

_ACTIVITY_BRIEF_FIELDS = {
    "process": ("operation", "executable", "command_line"),
    "network": ("operation", "protocol", "direction", "destination_endpoint_ref"),
    "socket": ("direction", "byte_count"),
    "file": ("operation", "path"),
    "service": ("operation", "service_ref"),
    "package": ("operation", "package_ref", "repository", "signature_valid"),
    "asset": ("operation",),
}


def _activity_brief(activity) -> str:
    fields = _ACTIVITY_BRIEF_FIELDS.get(activity.activity_type, ())
    details = "，".join(
        f"{key}={getattr(activity, key)}" for key in fields if getattr(activity, key) is not None
    )
    return f"{activity.activity_type}活动" + (f"（{details}）" if details else "")


def verified_behavior_briefs(state: InvestigationState) -> list[str]:
    """已验证行为构造：优先取已支持/已确认的 claim，回退到已授权活动摘要。"""

    verified = [
        claim.statement
        for claim in state.claims
        if claim.verification_state in ("supported", "confirmed")
    ]
    if verified:
        return verified[:_MAX_BEHAVIOR_BRIEFS]
    briefs: list[str] = []
    for result in state.tool_ledger.query_results:
        for activity in result.activities:
            briefs.append(_activity_brief(activity))
            if len(briefs) >= _MAX_BEHAVIOR_BRIEFS:
                return briefs
    return briefs


def open_hypothesis_briefs(state: InvestigationState) -> list[str]:
    return [
        claim.statement
        for claim in state.claims
        if claim.verification_state in ("unverified", "contradicted")
    ][:_MAX_BEHAVIOR_BRIEFS]


def build_baseline_consultation(state: InvestigationState) -> KnowledgeConsultation:
    return KnowledgeConsultation(
        scene="unknown_file_investigation",
        intent="investigation_guidance",
        context=KnowledgeConsultationContext(
            verified_behaviors=verified_behavior_briefs(state),
            open_hypotheses=open_hypothesis_briefs(state),
        ),
    )


def record_consultation(
    ledger: InvestigationToolLedger,
    result: KnowledgeConsultationResult,
    *,
    entry: str,
) -> KnowledgeConsultationRecord:
    record = KnowledgeConsultationRecord(
        consultation_id=result.consultation_id,
        query_id=result.query_id,
        entry=entry,
        intent=result.intent,
        status=result.status,
        item_refs=[
            f"{item.knowledge_id}@{item.version}#{item.chunk_id}" for item in result.items
        ],
        limitations=list(result.limitations),
    )
    ledger.knowledge_consultations.append(record)
    return record


def run_knowledge_baseline(
    state: InvestigationState,
    service,
) -> list[KnowledgeItem]:
    """执行基线检索并把合并后的调查指引挂到状态上；任何失败都不阻断。"""

    try:
        result = service.consult_investigation(build_baseline_consultation(state))
    except Exception as error:  # noqa: BLE001 — 只记录，不阻断研判主流程
        state.tool_ledger.knowledge_consultations.append(
            KnowledgeConsultationRecord(
                consultation_id="kcon-baseline-failed",
                query_id="kquery-baseline-failed",
                entry="baseline",
                intent="investigation_guidance",
                status="error",
                item_refs=[],
                limitations=[f"基线知识检索执行失败：{type(error).__name__}: {error}"],
            )
        )
        return []
    record_consultation(state.tool_ledger, result, entry="baseline")
    state.knowledge_guidance = list(result.items)
    return state.knowledge_guidance
