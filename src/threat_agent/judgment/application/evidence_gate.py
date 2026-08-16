from __future__ import annotations

from ...contracts import NormalizedActivity
from ...contracts.investigation import CandidateVerdict, VerdictLevel
from ..domain.models import InvestigationState


# Each threat type maps to the minimum evidence capabilities the run must have
# covered before a "confirmed_malicious" verdict is allowed. This is a floor,
# not a judgment rule: the gate only downgrades, it never upgrades, and it does
# not decide whether an activity is malicious.
REQUIRED_CAPABILITIES: dict[str, set[str]] = {
    "backdoor_c2": {"execution", "network"},
    "data_exfiltration": {"file_change", "network"},
    "ransomware": {"file_change"},
    "other": set(),
    "unknown": set(),
}

CAPABILITY_LABELS: dict[str, str] = {
    "execution": "进程/文件执行",
    "network": "网络连接",
    "file_change": "文件变更",
    "service_change": "服务变更",
}


def _activity_capabilities(activity: NormalizedActivity) -> set[str]:
    activity_type = activity.activity_type
    operation = getattr(activity, "operation", None)
    if activity_type == "process" and operation == "execute":
        return {"execution"}
    if activity_type == "file" and operation == "execute":
        return {"execution"}
    if activity_type == "network" and operation == "connect":
        return {"network"}
    if activity_type == "file" and operation in {"write", "rename", "delete"}:
        return {"file_change"}
    if activity_type == "service":
        return {"service_change"}
    return set()


def collect_capabilities(state: InvestigationState) -> set[str]:
    """Deterministically report which evidence capabilities the run covered.

    Purely observational: it only reports whether the run observed activity of
    a given kind, never whether that activity is malicious. The verdict gate
    does NOT use this — it builds capabilities only from the verdict's own
    citations (see ``cited_capabilities``).
    """

    capabilities: set[str] = set()
    for result in state.tool_ledger.query_results:
        for activity in result.activities:
            capabilities |= _activity_capabilities(activity)
    return capabilities


def resolve_cited_activity(state: InvestigationState, ref: str) -> NormalizedActivity | None:
    """Resolve a cited reference to the activity it points at, if reachable.

    Accepts activity ids and evidence-reference ids; only activities actually
    returned by this run's authorized tool results resolve.
    """

    reachable: dict[str, NormalizedActivity] = {}
    for result in state.tool_ledger.query_results:
        for activity in result.activities:
            reachable[activity.activity_id] = activity
    for result in state.tool_ledger.entity_results:
        for activity in result.timeline:
            reachable.setdefault(activity.activity_id, activity)
    activity_id = ref
    for result in state.tool_ledger.query_results:
        for item in result.evidence_references:
            if item.evidence_id == ref:
                activity_id = item.activity_ref
    return reachable.get(activity_id)


def cited_capabilities(state: InvestigationState, verdict: CandidateVerdict) -> set[str]:
    """Capabilities contributed by the activities the verdict actually cites.

    Data sitting in the tool ledger but never cited by the verdict cannot help
    it pass the evidence floor.
    """

    capabilities: set[str] = set()
    for ref in verdict.supporting_refs:
        activity = resolve_cited_activity(state, ref)
        if activity is not None:
            capabilities |= _activity_capabilities(activity)
    return capabilities


def gate_verdict(state: InvestigationState, verdict: CandidateVerdict) -> CandidateVerdict:
    """Downgrade a confirmed_malicious verdict whose cited evidence floor is unmet.

    Only downgrades; never upgrades, and never touches non-malicious levels.
    """

    if verdict.level != VerdictLevel.CONFIRMED_MALICIOUS:
        return verdict
    required = REQUIRED_CAPABILITIES.get(verdict.threat_type, set())
    capabilities = cited_capabilities(state, verdict)
    missing = required - capabilities
    if not missing:
        return verdict
    missing_labels = [CAPABILITY_LABELS.get(name, name) for name in sorted(missing)]
    limitation = (
        "证据门槛未满足：结论引用的证据缺少能力（"
        + "、".join(missing_labels)
        + "）。降级为可疑，建议进一步确认后重新研判。"
    )
    return verdict.model_copy(
        update={
            "level": VerdictLevel.SUSPICIOUS,
            "limitations": list(verdict.limitations) + [limitation],
        }
    )


__all__ = [
    "CAPABILITY_LABELS",
    "REQUIRED_CAPABILITIES",
    "cited_capabilities",
    "collect_capabilities",
    "gate_verdict",
    "resolve_cited_activity",
]
