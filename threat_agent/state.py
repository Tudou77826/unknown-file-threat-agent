from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from .models import AnalysisObligation, Coverage, Entity, EvidenceBundle, EvidenceStatus, FactFindingBundle, InvestigationState

if TYPE_CHECKING:
    from .tools import ToolRegistry


def _append_unique(target: list, values: list, key: str) -> None:
    existing = {getattr(x, key) for x in target}
    target.extend(x for x in values if getattr(x, key) not in existing)


def _merge_coverage(current: Coverage | None, incoming: Coverage) -> Coverage:
    if current is None:
        return incoming
    statuses = {current.status, incoming.status}
    if EvidenceStatus.ERROR in statuses:
        status = EvidenceStatus.ERROR
    elif EvidenceStatus.UNAVAILABLE in statuses:
        status = EvidenceStatus.UNAVAILABLE if statuses == {EvidenceStatus.UNAVAILABLE} else EvidenceStatus.PARTIAL
    elif EvidenceStatus.PARTIAL in statuses or statuses == {EvidenceStatus.AVAILABLE, EvidenceStatus.EMPTY}:
        status = EvidenceStatus.PARTIAL
    elif EvidenceStatus.AVAILABLE in statuses:
        status = EvidenceStatus.AVAILABLE
    else:
        status = EvidenceStatus.EMPTY
    starts = [value for value in (current.requested_start, incoming.requested_start) if value]
    ends = [value for value in (current.requested_end, incoming.requested_end) if value]
    available_starts = [value for value in (current.available_start, incoming.available_start) if value]
    available_ends = [value for value in (current.available_end, incoming.available_end) if value]
    return Coverage(
        domain=incoming.domain,
        status=status,
        host_id=incoming.host_id or current.host_id,
        source_system=incoming.source_system or current.source_system,
        completeness=(
            "unavailable" if status in {EvidenceStatus.UNAVAILABLE, EvidenceStatus.ERROR}
            else "partial" if "partial" in {current.completeness, incoming.completeness}
            else "complete" if {current.completeness, incoming.completeness} == {"complete"}
            else "unknown"
        ),
        requested_start=min(starts) if starts else None,
        requested_end=max(ends) if ends else None,
        available_start=min(available_starts) if available_starts else None,
        available_end=max(available_ends) if available_ends else None,
        result_start=min(value for value in (current.result_start, incoming.result_start) if value) if any((current.result_start, incoming.result_start)) else None,
        result_end=max(value for value in (current.result_end, incoming.result_end) if value) if any((current.result_end, incoming.result_end)) else None,
        limitations=list(dict.fromkeys([*current.limitations, *incoming.limitations])),
    )


def apply_evidence_bundle(
    state: InvestigationState,
    bundle: EvidenceBundle,
    registry: "ToolRegistry",
    requested_evidence_types: set[str] | frozenset[str] | None = None,
) -> None:
    _append_unique(state.evidence, bundle.evidence, "evidence_id")
    state.coverage[bundle.coverage.domain] = _merge_coverage(
        state.coverage.get(bundle.coverage.domain), bundle.coverage
    )
    returned_types = {e.evidence_type for e in bundle.evidence if e.status == EvidenceStatus.AVAILABLE}
    requested_types = set(requested_evidence_types or returned_types)
    for gap in state.evidence_gaps:
        relevant = bool(returned_types & set(gap.required_evidence_types))
        request_match = bool(requested_types & set(gap.required_evidence_types))
        if relevant:
            gap.status = "evidence_collected"
        elif request_match and bundle.status in {EvidenceStatus.UNAVAILABLE, EvidenceStatus.ERROR}:
            gap.status = "unresolvable"
            gap.resolution = "unresolvable"
            gap.limitations = list(dict.fromkeys([*gap.limitations, *bundle.limitations]))
        elif request_match and not bundle.evidence:
            exhaustive_request = requested_types >= set(gap.required_evidence_types)
            if bundle.status == EvidenceStatus.EMPTY and bundle.coverage.completeness == "complete" and exhaustive_request:
                gap.status = "resolved"
                gap.resolution = "negative"
            else:
                gap.status = "partially_resolved"
                gap.resolution = "partial"
            gap.limitations = list(dict.fromkeys([*gap.limitations, *bundle.limitations]))

    available_types = {e.evidence_type for e in state.evidence if e.status == EvidenceStatus.AVAILABLE}
    for role in state.evidence_roles:
        required = set(role.required_evidence_types)
        present = required & available_types
        role.satisfied_by_refs = sorted(
            e.evidence_id for e in state.evidence
            if e.status == EvidenceStatus.AVAILABLE and e.evidence_type in required
        )
        requirement_met = bool(required & available_types) if role.requirement_mode == "any" else required <= available_types
        if required and requirement_met:
            role.status = "satisfied"
        elif present:
            role.status = "partially_satisfied"
        elif any(
            state.coverage.get(domain) and state.coverage[domain].status in {EvidenceStatus.UNAVAILABLE, EvidenceStatus.ERROR}
            for domain in {e.domain for e in state.evidence if e.evidence_type in required}
        ):
            role.status = "unavailable"

    available = [e for e in state.evidence if e.status == EvidenceStatus.AVAILABLE]
    existing = {(item.tool_name, tuple(sorted(item.evidence_refs))) for item in state.analysis_obligations}
    for tool in registry.list():
        if tool.kind != "analysis":
            continue
        refs = sorted(e.evidence_id for e in available if e.evidence_type in tool.requires_evidence_types)
        present_types = {e.evidence_type for e in available if e.evidence_id in refs}
        requirements_met = (
            bool(tool.requires_evidence_types & present_types)
            if tool.requirements_mode == "any"
            else tool.requires_evidence_types <= present_types
        )
        if not refs or not requirements_met:
            continue
        fingerprint = (tool.name, tuple(refs))
        if fingerprint in existing:
            continue
        gap_ids = [
            gap.gap_id for gap in state.evidence_gaps
            if gap.gap_type in tool.resolves_gap_types
        ]
        if not gap_ids:
            continue
        digest = hashlib.sha256(f"{tool.name}:{','.join(refs)}".encode()).hexdigest()[:12]
        state.analysis_obligations.append(AnalysisObligation(
            obligation_id=f"obligation-{digest}",
            tool_name=tool.name,
            reason=f"Collected evidence satisfies the prerequisites for {tool.name}",
            evidence_refs=refs,
            gap_ids=gap_ids,
            primary_gap_id=gap_ids[0],
        ))
        existing.add(fingerprint)


def apply_analysis_bundle(
    state: InvestigationState,
    bundle: FactFindingBundle,
    tool_name: str,
    evidence_refs: list[str],
) -> None:
    _append_unique(state.facts, bundle.facts, "fact_id")
    _append_unique(state.findings, bundle.findings, "finding_id")
    _append_unique(state.relations, bundle.relations, "relation_id")
    known_entities = {entity.entity_id for entity in state.entities}
    entity_types = {
        "host": "host",
        "file": "file",
        "process": "process",
        "endpoint": "network_endpoint",
        "persistence": "persistence",
        "user": "user",
        "container": "container",
        "session": "session",
        "archive": "archive",
        "package": "package",
        "service": "service",
        "directory": "directory",
        "data": "data_object",
        "credential": "credential",
    }
    for relation in bundle.relations:
        for entity_ref in (relation.source_entity_ref, relation.target_entity_ref):
            if entity_ref in known_entities:
                continue
            prefix = entity_ref.split(":", 1)[0]
            entity_type = entity_types.get(prefix)
            if entity_type:
                state.entities.append(Entity(entity_id=entity_ref, entity_type=entity_type, attributes={"derived": True}))
                known_entities.add(entity_ref)
    selected = tuple(sorted(set(evidence_refs)))
    for obligation in state.analysis_obligations:
        if obligation.tool_name == tool_name and tuple(sorted(obligation.evidence_refs)) == selected:
            obligation.status = "completed"
            obligation.outcome = "positive" if bundle.facts or bundle.findings or bundle.relations else "negative"
            obligation.result_refs = [
                *[item.fact_id for item in bundle.facts],
                *[item.finding_id for item in bundle.findings],
                *[item.relation_id for item in bundle.relations],
            ]
            obligation.limitations = list(bundle.limitations)
    for gap in state.evidence_gaps:
        related = [item for item in state.analysis_obligations if gap.gap_id in item.gap_ids]
        if related and all(item.status == "completed" for item in related):
            gap.status = "resolved"
            positive = [item for item in related if item.outcome == "positive"]
            gap.resolution = "positive" if positive else "negative"
            gap.resolution_refs = sorted({ref for item in related for ref in item.result_refs})
            gap.limitations = list(dict.fromkeys(item for obligation in related for item in obligation.limitations))
        elif any(item.status == "running" for item in related):
            gap.status = "analyzing"
        elif any(item.status == "failed" for item in related):
            gap.status = "partially_resolved"
            gap.resolution = "partial"
    update_hypotheses(state)


def update_hypotheses(state: InvestigationState) -> None:
    if not state.hypotheses:
        return
    fact_types = {x.fact_type for x in state.facts}
    finding_types = {x.finding_type for x in state.findings}
    for hyp in state.hypotheses:
        if hyp.hypothesis_type == "backdoor_c2":
            support = [x.fact_id for x in state.facts if x.fact_type in {"file_executed", "external_connection_observed", "persistence_configuration_observed"}]
            support += [x.finding_id for x in state.findings if x.finding_type in {"periodic_external_connection", "remote_command_execution", "active_persistence"}]
            contradict = [x.finding_id for x in state.findings if x.finding_type == "legitimate_software_explanation"]
            hyp.supporting_refs = support
            hyp.contradicting_refs = contradict
            hyp.missing_evidence_gap_refs = [g.gap_id for g in state.evidence_gaps if g.status not in {"resolved", "unresolvable"}]
            score = 0.1 + 0.15 * ("file_executed" in fact_types) + 0.2 * ("periodic_external_connection" in finding_types) + 0.3 * ("remote_command_execution" in finding_types) + 0.15 * ("active_persistence" in finding_types) - 0.5 * bool(contradict)
            hyp.confidence = max(0.0, min(1.0, score))
            hyp.status = "rejected" if contradict and "remote_command_execution" not in finding_types else ("supported" if hyp.confidence >= 0.45 else "open")
        elif hyp.hypothesis_type == "file_provenance":
            origin_fact_types = {"file_created", "file_downloaded", "file_transferred", "file_extracted_from_archive", "file_installed_by_package", "file_uploaded_through_web_service"}
            support = [item.fact_id for item in state.facts if item.fact_type in origin_fact_types]
            gap = next((item for item in state.evidence_gaps if item.gap_type == "file_origin"), None)
            hyp.supporting_refs = support
            hyp.contradicting_refs = []
            hyp.missing_evidence_gap_refs = [gap.gap_id] if gap and gap.status not in {"resolved", "unresolvable"} else []
            if support:
                hyp.confidence = min(0.98, 0.7 + 0.08 * len(support))
                hyp.status = "supported"
            elif gap and gap.resolution == "negative":
                hyp.confidence = 0.0
                hyp.status = "rejected"
            else:
                hyp.confidence = 0.2
                hyp.status = "open"
        elif hyp.hypothesis_type == "data_exfiltration":
            support_fact_types = {
                "sensitive_discovery_observed", "sensitive_file_read",
                "sensitive_archive_created", "sensitive_staging_file_created",
                "outbound_data_transfer", "encoded_dns_query_sequence",
            }
            support_finding_types = {
                "sensitive_data_discovery", "credential_access", "sensitive_data_access",
                "sensitive_data_staging", "high_volume_external_transfer",
                "dns_tunnel_pattern", "confirmed_data_exfiltration",
            }
            support = [item.fact_id for item in state.facts if item.fact_type in support_fact_types]
            support += [item.finding_id for item in state.findings if item.finding_type in support_finding_types]
            contradict = [item.finding_id for item in state.findings if item.finding_type == "legitimate_backup_explanation"]
            hyp.supporting_refs = support
            hyp.contradicting_refs = contradict
            relevant_gap_types = {"sensitive_discovery", "sensitive_access", "data_staging", "data_transfer", "dns_tunnel", "exfiltration", "transfer_counter"}
            hyp.missing_evidence_gap_refs = [
                gap.gap_id for gap in state.evidence_gaps
                if gap.gap_type in relevant_gap_types and gap.status not in {"resolved", "unresolvable"}
            ]
            if "confirmed_data_exfiltration" in finding_types:
                hyp.confidence, hyp.status = 0.98, "confirmed"
            elif contradict:
                hyp.confidence, hyp.status = 0.05, "rejected"
            elif "sensitive_data_staging" in finding_types and (
                "high_volume_external_transfer" in finding_types or "dns_tunnel_pattern" in finding_types
            ):
                hyp.confidence, hyp.status = 0.72, "supported"
            elif support:
                hyp.confidence, hyp.status = min(0.6, 0.18 + 0.06 * len(support)), "open"
            else:
                hyp.confidence, hyp.status = 0.1, "open"
        elif hyp.hypothesis_type == "ransomware":
            support_types = {"broad_high_rate_file_impact", "probable_file_encryption", "recovery_inhibition", "ransom_demand_marker", "actual_service_disruption", "confirmed_ransomware_impact"}
            support = [item.finding_id for item in state.findings if item.finding_type in support_types]
            contradict = [item.finding_id for item in state.findings if item.finding_type == "legitimate_batch_explanation"]
            hyp.supporting_refs, hyp.contradicting_refs = support, contradict
            gap_types = {"bulk_file_impact", "file_encryption", "recovery_inhibition", "service_disruption", "ransom_note", "ransomware_counter", "ransomware_chain"}
            hyp.missing_evidence_gap_refs = [gap.gap_id for gap in state.evidence_gaps if gap.gap_type in gap_types and gap.status not in {"resolved", "unresolvable"}]
            if "confirmed_ransomware_impact" in finding_types:
                hyp.confidence, hyp.status = 0.99, "confirmed"
            elif contradict:
                hyp.confidence, hyp.status = 0.05, "rejected"
            elif "broad_high_rate_file_impact" in finding_types and "probable_file_encryption" in finding_types:
                hyp.confidence, hyp.status = 0.78, "supported"
            else:
                hyp.confidence, hyp.status = min(0.65, 0.15 + 0.1 * len(support)), "open"
        elif hyp.hypothesis_type == "cross_host_propagation":
            support_types = {"cross_host_transfer_lead", "confirmed_lateral_file_propagation"}
            support = [item.finding_id for item in state.findings if item.finding_type in support_types]
            contradict = [item.finding_id for item in state.findings if item.finding_type in {"legitimate_multi_host_deployment", "shared_infrastructure_only"}]
            hyp.supporting_refs, hyp.contradicting_refs = support, contradict
            hyp.missing_evidence_gap_refs = [gap.gap_id for gap in state.evidence_gaps if gap.gap_type.startswith("cross_host_") and gap.status not in {"resolved", "unresolvable"}]
            if "confirmed_lateral_file_propagation" in finding_types:
                hyp.confidence, hyp.status = 0.98, "confirmed"
            elif contradict:
                hyp.confidence, hyp.status = 0.05, "rejected"
            elif support:
                hyp.confidence, hyp.status = 0.65, "supported"
            else:
                hyp.confidence, hyp.status = 0.15, "open"
