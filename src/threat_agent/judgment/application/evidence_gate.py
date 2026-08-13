from __future__ import annotations

from typing import Iterable

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


def collect_capabilities(state: InvestigationState) -> set[str]:
    """Deterministically report which evidence capabilities the run covered.

    Purely observational: it only reports whether the run observed activity of
    a given kind, never whether that activity is malicious.
    """

    capabilities: set[str] = set()
    for result in state.tool_ledger.query_results:
        for activity in result.activities:
            activity_type = activity.activity_type
            operation = getattr(activity, "operation", None)
            if activity_type == "process" and operation == "execute":
                capabilities.add("execution")
            elif activity_type == "file" and operation == "execute":
                capabilities.add("execution")
            elif activity_type == "network" and operation == "connect":
                capabilities.add("network")
            elif activity_type == "file" and operation in {"write", "rename", "delete"}:
                capabilities.add("file_change")
            elif activity_type == "service":
                capabilities.add("service_change")
    return capabilities


def gate_verdict(state: InvestigationState, verdict: CandidateVerdict) -> CandidateVerdict:
    """Downgrade a confirmed_malicious verdict whose evidence floor is unmet.

    Only downgrades; never upgrades, and never touches non-malicious levels.
    """

    if verdict.level != VerdictLevel.CONFIRMED_MALICIOUS:
        return verdict
    required = REQUIRED_CAPABILITIES.get(verdict.threat_type, set())
    capabilities = collect_capabilities(state)
    missing = required - capabilities
    if not missing:
        return verdict
    missing_labels = [CAPABILITY_LABELS.get(name, name) for name in sorted(missing)]
    limitation = (
        "证据门槛未满足：确认恶意缺少证据能力（"
        + "、".join(missing_labels)
        + "）。降级为可疑，建议进一步确认后重新研判。"
    )
    return verdict.model_copy(
        update={
            "level": VerdictLevel.SUSPICIOUS,
            "limitations": list(verdict.limitations) + [limitation],
        }
    )


def gate_verdict_draft(state: InvestigationState, verdict: CandidateVerdict) -> CandidateVerdict:
    """Convenience alias kept for clarity at the call site."""
    return gate_verdict(state, verdict)


__all__ = [
    "CAPABILITY_LABELS",
    "REQUIRED_CAPABILITIES",
    "collect_capabilities",
    "gate_verdict",
    "gate_verdict_draft",
]
