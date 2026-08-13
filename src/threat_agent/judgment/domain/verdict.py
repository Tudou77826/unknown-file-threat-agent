from __future__ import annotations

from .models import CandidateVerdict, EvidenceStatus, InvestigationState, VerdictLevel


def build_attack_path(state: InvestigationState) -> list[dict]:
    return [r.model_dump(mode="json") for r in sorted(state.relations, key=lambda x: x.observed_at.isoformat() if x.observed_at else "9999")]


def evaluate_verdict(state: InvestigationState) -> CandidateVerdict:
    facts = {x.fact_type: x for x in state.facts}
    findings = {x.finding_type: x for x in state.findings}
    def refs_for(*types: str) -> list[str]:
        refs: list[str] = []
        for item_type in types:
            item = facts.get(item_type) or findings.get(item_type)
            if item is not None:
                refs.append(getattr(item, "fact_id", None) or getattr(item, "finding_id"))
        return refs

    benign = "legitimate_software_explanation" in findings
    remote_command = "remote_command_execution" in findings
    executed = "file_executed" in facts
    periodic = "periodic_external_connection" in findings
    persistence = "active_persistence" in findings
    confirmed_exfil = "confirmed_data_exfiltration" in findings
    legitimate_transfer = "legitimate_backup_explanation" in findings
    sensitive_access = bool({"credential_access", "sensitive_data_access"} & findings.keys())
    staged = "sensitive_data_staging" in findings
    transfer = "high_volume_external_transfer" in findings
    dns_tunnel = "dns_tunnel_pattern" in findings
    confirmed_ransomware = "confirmed_ransomware_impact" in findings
    legitimate_batch = "legitimate_batch_explanation" in findings
    broad_impact = "broad_high_rate_file_impact" in findings
    probable_encryption = "probable_file_encryption" in findings
    destructive_impact = bool({"recovery_inhibition", "ransom_demand_marker", "actual_service_disruption"} & findings.keys())
    lateral_propagation = "confirmed_lateral_file_propagation" in findings
    legitimate_deployment = "legitimate_multi_host_deployment" in findings
    unavailable = [d for d, c in state.coverage.items() if c.status in {EvidenceStatus.UNAVAILABLE, EvidenceStatus.ERROR}]
    incomplete = [d for d, c in state.coverage.items() if c.completeness in {"partial", "unknown", "unavailable"}]

    if lateral_propagation and not legitimate_deployment:
        return CandidateVerdict(level=VerdictLevel.LIKELY_MALICIOUS, threat_type="other", summary="The investigated file was transferred to another host through a related authenticated session and executed there", supporting_refs=refs_for("file_executed", "cross_host_file_transfer_observed", "confirmed_lateral_file_propagation"), contradicting_refs=refs_for("legitimate_multi_host_deployment"), limitations=["The upstream exploit or credential-compromise mechanism may require additional evidence"])
    if legitimate_deployment and not lateral_propagation:
        return CandidateVerdict(level=VerdictLevel.BENIGN, threat_type="unknown", summary="Approved deployment context explains transfer and presence of the file on multiple hosts", supporting_refs=refs_for("legitimate_multi_host_deployment"), contradicting_refs=refs_for("cross_host_transfer_lead"))
    if confirmed_ransomware and not legitimate_batch:
        return CandidateVerdict(level=VerdictLevel.CONFIRMED_MALICIOUS, threat_type="ransomware", summary="The investigated process executed and caused broad encryption-like file transformation with destructive ransomware impact", supporting_refs=refs_for("file_executed", "broad_high_rate_file_impact", "probable_file_encryption", "recovery_inhibition", "ransom_demand_marker", "actual_service_disruption", "confirmed_ransomware_impact"), contradicting_refs=refs_for("legitimate_batch_explanation"))
    if legitimate_batch and not confirmed_ransomware:
        level = VerdictLevel.BENIGN if executed and not incomplete else VerdictLevel.LIKELY_BENIGN
        return CandidateVerdict(level=level, threat_type="unknown", summary="An approved process, change window and target scope explain the broad batch file transformation", supporting_refs=refs_for("legitimate_batch_explanation"), contradicting_refs=refs_for("broad_high_rate_file_impact", "probable_file_encryption"), limitations=(["Incomplete evidence coverage: " + ", ".join(sorted(incomplete))] if incomplete else []))
    if broad_impact and probable_encryption:
        return CandidateVerdict(level=VerdictLevel.LIKELY_MALICIOUS, threat_type="ransomware", summary="Broad high-rate impact and encryption-like transformations are proven, but the complete destructive ransomware chain is incomplete", supporting_refs=refs_for("file_executed", "broad_high_rate_file_impact", "probable_file_encryption", "recovery_inhibition", "ransom_demand_marker"), limitations=[] if destructive_impact else ["No successful recovery inhibition, service disruption or repeated ransom note was proven"])
    if broad_impact or probable_encryption or destructive_impact:
        return CandidateVerdict(level=VerdictLevel.SUSPICIOUS, threat_type="ransomware", summary="A ransomware-related behavior was observed, but actual broad encryption and impact are not both proven", supporting_refs=refs_for("broad_high_rate_file_impact", "probable_file_encryption", "recovery_inhibition", "ransom_demand_marker", "actual_service_disruption"))
    if confirmed_exfil and not legitimate_transfer:
        return CandidateVerdict(
            level=VerdictLevel.CONFIRMED_MALICIOUS,
            threat_type="data_exfiltration",
            summary="The investigated process read sensitive data, staged it, and transferred the same data object through an unapproved channel",
            supporting_refs=refs_for("file_executed", "sensitive_file_read", "sensitive_data_staging", "outbound_data_transfer", "dns_tunnel_pattern", "confirmed_data_exfiltration"),
            contradicting_refs=refs_for("legitimate_backup_explanation"),
        )
    if legitimate_transfer and not confirmed_exfil:
        level = VerdictLevel.BENIGN if executed and not incomplete else VerdictLevel.LIKELY_BENIGN
        limitations = (["Incomplete evidence coverage: " + ", ".join(sorted(incomplete))] if incomplete else [])
        return CandidateVerdict(
            level=level,
            threat_type="unknown",
            summary="An approved process-and-destination baseline explains the sensitive data transfer",
            supporting_refs=refs_for("legitimate_backup_explanation"),
            contradicting_refs=refs_for("sensitive_data_staging", "high_volume_external_transfer", "dns_tunnel_pattern"),
            limitations=limitations,
        )
    if staged and (transfer or dns_tunnel):
        return CandidateVerdict(
            level=VerdictLevel.LIKELY_MALICIOUS,
            threat_type="data_exfiltration",
            summary="Sensitive data staging and suspicious egress were established, but the transmitted content was not conclusively linked",
            supporting_refs=refs_for("sensitive_data_staging", "high_volume_external_transfer", "dns_tunnel_pattern"),
            limitations=["No complete transmitted-object or encoded-payload correlation was established"],
        )
    if sensitive_access or staged or dns_tunnel:
        return CandidateVerdict(
            level=VerdictLevel.SUSPICIOUS,
            threat_type="data_exfiltration",
            summary="One or more data-theft behaviors were observed, but the complete collection and egress chain is not proven",
            supporting_refs=refs_for("credential_access", "sensitive_data_access", "sensitive_data_staging", "dns_tunnel_pattern"),
            limitations=["Available evidence does not establish an end-to-end data-exfiltration chain"],
        )
    if benign and not remote_command:
        level = VerdictLevel.BENIGN if executed and not incomplete else VerdictLevel.LIKELY_BENIGN
        limitations = (["Incomplete evidence coverage: " + ", ".join(sorted(incomplete))] if incomplete else [])
        return CandidateVerdict(
            level=level,
            threat_type="unknown",
            summary="Trusted provenance and approved service behavior explain the observed activity",
            supporting_refs=refs_for("trusted_package_provenance", "known_service_endpoint", "legitimate_software_explanation"),
            contradicting_refs=refs_for("periodic_external_connection", "active_persistence"),
            limitations=limitations,
        )
    if executed and remote_command and persistence:
        return CandidateVerdict(level=VerdictLevel.CONFIRMED_MALICIOUS, threat_type="backdoor_c2", summary="The unknown file executed, established active persistence, and participated in correlated remote command execution", supporting_refs=refs_for("file_executed", "external_connection_observed", "remote_command_execution", "active_persistence"), contradicting_refs=refs_for("legitimate_software_explanation"))
    if executed and periodic and persistence:
        return CandidateVerdict(level=VerdictLevel.LIKELY_MALICIOUS, threat_type="backdoor_c2", summary="Execution, active persistence, and periodic external communication strongly support a backdoor/C2 hypothesis", supporting_refs=refs_for("file_executed", "external_connection_observed", "periodic_external_connection", "active_persistence"), contradicting_refs=refs_for("legitimate_software_explanation"), limitations=["No direct remote-command evidence was observed"])
    if executed and (periodic or persistence):
        return CandidateVerdict(level=VerdictLevel.SUSPICIOUS, threat_type="backdoor_c2", summary="The file executed and exhibited a suspicious runtime behavior, but the complete C2 chain is not proven", supporting_refs=refs_for("file_executed", "periodic_external_connection", "active_persistence"), contradicting_refs=refs_for("legitimate_software_explanation"))
    limitations = ["Independent evidence does not establish a complete malicious behavior chain"]
    if unavailable:
        limitations.append("Unavailable evidence domains: " + ", ".join(sorted(unavailable)))
    return CandidateVerdict(level=VerdictLevel.INSUFFICIENT_EVIDENCE, threat_type="unknown", summary="Available evidence is insufficient to determine whether the unknown file participated in an attack", supporting_refs=refs_for("file_executed", "external_connection_observed"), limitations=limitations)


def validate_verdict(state: InvestigationState, verdict: CandidateVerdict) -> list[str]:
    errors = []
    evidence_ids = {item.evidence_id for item in state.evidence}
    entity_ids = {item.entity_id for item in state.entities}
    fact_ids = {item.fact_id for item in state.facts}
    known = {x.fact_id for x in state.facts} | {x.finding_id for x in state.findings}
    missing = (set(verdict.supporting_refs) | set(verdict.contradicting_refs)) - known
    if missing:
        errors.append(f"Verdict references unknown facts/findings: {sorted(missing)}")
    for fact in state.facts:
        unresolved = set(fact.evidence_refs) - evidence_ids
        if unresolved:
            errors.append(f"Fact {fact.fact_id} references unknown evidence: {sorted(unresolved)}")
    for finding in state.findings:
        unresolved = set(finding.evidence_refs) - evidence_ids
        if unresolved:
            errors.append(f"Finding {finding.finding_id} references unknown evidence: {sorted(unresolved)}")
        missing_facts = set(finding.supporting_fact_refs) - fact_ids
        if missing_facts:
            errors.append(f"Finding {finding.finding_id} references unknown facts: {sorted(missing_facts)}")
    for relation in state.relations:
        unresolved = set(relation.evidence_refs) - evidence_ids
        if unresolved:
            errors.append(f"Relation {relation.relation_id} references unknown evidence: {sorted(unresolved)}")
        missing_entities = {relation.source_entity_ref, relation.target_entity_ref} - entity_ids
        if missing_entities:
            errors.append(f"Relation {relation.relation_id} references unknown entities: {sorted(missing_entities)}")
    if verdict.level == VerdictLevel.CONFIRMED_MALICIOUS:
        fact_types = {x.fact_type for x in state.facts}
        finding_types = {x.finding_type for x in state.findings}
        if verdict.threat_type == "data_exfiltration":
            required = {"file_executed", "sensitive_file_read"} - fact_types
            if required or "confirmed_data_exfiltration" not in finding_types:
                errors.append("Confirmed data-exfiltration verdict lacks mandatory execution, sensitive-read, or correlated exfiltration proof")
            chain = [item for item in state.findings if item.finding_type == "confirmed_data_exfiltration"]
            evidence_by_id = {item.evidence_id: item for item in state.evidence}
            for item in chain:
                types = {evidence_by_id[ref].evidence_type for ref in item.evidence_refs if ref in evidence_by_id}
                required_chain = {"sensitive_file_access", "archive_create", "archive_member"}
                if not required_chain <= types or not ({"network_transfer", "http_upload", "dns_query"} & types) or "transfer_baseline" not in types:
                    errors.append(f"Finding {item.finding_id} lacks a complete sensitive-access, staging, egress, and baseline evidence chain")
        elif verdict.threat_type == "ransomware":
            required = {"file_executed"} - fact_types
            required_findings = {"broad_high_rate_file_impact", "probable_file_encryption", "confirmed_ransomware_impact"} - finding_types
            if required or required_findings:
                errors.append("Confirmed ransomware verdict lacks mandatory execution, broad impact, encryption transformation, or complete-chain proof")
            chains = [item for item in state.findings if item.finding_type == "confirmed_ransomware_impact"]
            evidence_by_id = {item.evidence_id: item for item in state.evidence}
            for item in chains:
                types = {evidence_by_id[ref].evidence_type for ref in item.evidence_refs if ref in evidence_by_id}
                if not {"bulk_file_metric", "file_content_change", "file_rename_pattern", "authorized_batch_baseline"} <= types or not ({"backup_destruction", "snapshot_activity", "ransom_note"} & types):
                    errors.append(f"Finding {item.finding_id} lacks complete bulk-impact, encryption, destructive-impact, and baseline evidence")
        else:
            required = {"file_executed"} - fact_types
            required_findings = {"active_persistence", "remote_command_execution"} - finding_types
            if required or required_findings:
                errors.append("Confirmed malicious verdict lacks mandatory execution, persistence, or remote-command proof")
    return errors
