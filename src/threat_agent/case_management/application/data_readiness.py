from __future__ import annotations

from collections import defaultdict

from ...contracts import (
    Coverage,
    DataProfile,
    DataReadinessReport,
    EvidenceStatus,
    ReadinessQuestion,
)


# Static investigation questions the demo presents. Each maps the data sources
# required to answer it; readiness is derived purely from the profile's visible
# sources, not from any running investigation state.
READINESS_QUESTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "role-execution": ("这个未知文件是否真的运行过？", ("edr-process",)),
    "role-attribution": ("后续行为是否由该文件产生？", ("edr-process",)),
    "role-c2-behavior": ("它是否外联并接收远程命令？", ("edr-network", "ebpf-socket", "auditd-execve")),
    "role-persistence": ("它是否建立了持续驻留机制？", ("auditd-file", "package-manager", "systemd-journal")),
    "role-counter-evidence": ("它是否可能是批准的合法软件？", ("rpm-inventory", "cmdb-baseline")),
}

SOURCE_DOMAINS: dict[str, str] = {
    "edr-process": "process",
    "auditd-execve": "process",
    "edr-network": "network",
    "ebpf-socket": "network",
    "auditd-file": "file",
    "package-manager": "file",
    "systemd-journal": "persistence",
    "rpm-inventory": "reputation",
    "cmdb-baseline": "reputation",
}


def _question(question_id: str, question: str, sources: tuple[str, ...], profile: DataProfile) -> ReadinessQuestion:
    visible = set(profile.visible_sources)
    present = [source for source in sources if source in visible]
    status = (
        "answerable" if len(present) == len(sources)
        else "partially_answerable" if present
        else "blocked"
    )
    limitations = []
    if status != "answerable":
        limitations.append(f"Missing data sources: {sorted(set(sources) - set(present))}")
    return ReadinessQuestion(
        question_id=question_id,
        question=question,
        evidence_role_ids=[question_id],
        required_domains=[SOURCE_DOMAINS.get(source, "unknown") for source in sources],
        required_sources=list(sources),
        status=status,
        limitations=limitations,
    )


def evaluate_data_readiness(
    profile: DataProfile,
    *,
    case_id: str,
    tenant_id: str,
    run_id: str,
) -> DataReadinessReport:
    """Explain which investigation questions the selected data profile can support.

    Deterministic and descriptive: derived purely from profile.visible_sources.
    """

    questions = [
        _question(question_id, question, sources, profile)
        for question_id, (question, sources) in READINESS_QUESTIONS.items()
    ]
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
        case_id=case_id,
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
