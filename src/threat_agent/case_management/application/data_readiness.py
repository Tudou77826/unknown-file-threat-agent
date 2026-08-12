from __future__ import annotations

from collections import defaultdict

from ...contracts import (
    Coverage,
    DataProfile,
    DataReadinessReport,
    EvidenceStatus,
    ReadinessQuestion,
)
from ...judgment.domain.models import EvidenceRole, InvestigationState


EVIDENCE_CAPABILITIES: dict[str, tuple[str, tuple[str, ...]]] = {
    "process_exec": ("process", ("edr-process",)),
    "process_parent_relation": ("process", ("edr-process",)),
    "child_process_exec": ("process", ("auditd-execve",)),
    "network_connection": ("network", ("edr-network",)),
    "socket_io": ("network", ("ebpf-socket",)),
    "systemd_event": ("persistence", ("auditd-file", "package-manager", "systemd-journal")),
    "package_provenance": ("reputation", ("rpm-inventory",)),
    "approved_endpoint": ("reputation", ("cmdb-baseline",)),
}


def _question(role: EvidenceRole, profile: DataProfile) -> ReadinessQuestion:
    visible = set(profile.visible_sources)
    type_ready: list[bool] = []
    domains: list[str] = []
    sources: list[str] = []
    limitations: list[str] = []
    for evidence_type in role.required_evidence_types:
        capability = EVIDENCE_CAPABILITIES.get(evidence_type)
        if capability is None:
            type_ready.append(False)
            limitations.append(f"No data-capability mapping exists for {evidence_type}")
            continue
        domain, candidates = capability
        domains.append(domain)
        sources.extend(candidates)
        type_ready.append(bool(visible.intersection(candidates)))
    ready_count = sum(type_ready)
    if type_ready and (
        (role.requirement_mode == "all" and ready_count == len(type_ready))
        or (role.requirement_mode == "any" and ready_count > 0)
    ):
        status = "answerable"
    elif ready_count:
        status = "partially_answerable"
        limitations.append("Only part of the required evidence capability is exposed")
    else:
        status = "blocked"
        limitations.append("None of the required evidence sources is exposed")
    return ReadinessQuestion(
        question_id=role.role_id,
        question=role.question,
        evidence_role_ids=[role.role_id],
        required_domains=list(dict.fromkeys(domains)),
        required_sources=list(dict.fromkeys(sources)),
        status=status,
        limitations=limitations,
    )


def evaluate_data_readiness(
    state: InvestigationState,
    profile: DataProfile,
    *,
    tenant_id: str,
    run_id: str,
) -> DataReadinessReport:
    """Explain which investigation questions the selected data profile can support.

    This evaluator is deterministic and descriptive. It does not modify investigation
    state or infer a threat verdict.
    """

    questions = [_question(role, profile) for role in state.evidence_roles]
    by_domain: dict[str, list] = defaultdict(list)
    for rule in profile.coverage_rules:
        for domain in rule.domains:
            by_domain[domain].append(rule)
    coverage_summary: dict[str, Coverage] = {}
    for domain in sorted({domain for item in questions for domain in item.required_domains}):
        rules = by_domain.get(domain, [])
        if not rules:
            coverage_summary[domain] = Coverage(
                domain=domain,
                status=EvidenceStatus.UNAVAILABLE,
                completeness="unavailable",
                limitations=["No visible source covers this investigation domain"],
            )
            continue
        complete = any(rule.completeness == "complete" for rule in rules)
        coverage_summary[domain] = Coverage(
            domain=domain,
            status=EvidenceStatus.AVAILABLE if complete else EvidenceStatus.PARTIAL,
            source_system=",".join(rule.source_id for rule in rules),
            completeness="complete" if complete else "partial",
            limitations=list(dict.fromkeys(x for rule in rules for x in rule.limitations)),
        )
    required_sources = list(
        dict.fromkeys(source for item in questions for source in item.required_sources)
    )
    missing_sources = [source for source in required_sources if source not in profile.visible_sources]
    recommended = [f"Connect or expose data source: {source}" for source in missing_sources]
    return DataReadinessReport(
        tenant_id=tenant_id,
        case_id=state.case_id,
        source_identity="case-management/data-readiness",
        run_id=run_id,
        profile_id=profile.profile_id,
        dataset_version=profile.dataset_version,
        available_sources=list(profile.visible_sources),
        missing_sources=missing_sources,
        answerable_questions=[item for item in questions if item.status != "blocked"],
        blocked_questions=[item for item in questions if item.status == "blocked"],
        coverage_summary=coverage_summary,
        recommended_capabilities=recommended,
        limitations=[
            "Readiness describes source capability, not whether a threat is present",
            "Reference data is synthetic and must not be treated as production telemetry",
        ],
    )
