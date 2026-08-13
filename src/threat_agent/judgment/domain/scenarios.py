from __future__ import annotations

from typing import Any

from .models import EvidenceGap, EvidenceRole, Hypothesis, Interpretation, InvestigationState


SCENARIO_CATALOG: dict[str, dict[str, Any]] = {
    "c2": {
        "description": "Investigate process attribution, external communication, remote command execution, persistence and legitimate software explanations.",
        "recommended_tools": ["query_process_relations", "query_process_network", "query_socket_activity", "query_child_process_execution", "query_systemd_events", "query_package_provenance", "query_approved_endpoints"],
    },
    "file_provenance": {
        "description": "Determine whether the file was created, downloaded, transferred, extracted, installed by a package, or uploaded through a web service.",
        "recommended_tools": [
            "query_file_origin",
            "query_file_downloads",
            "query_file_transfer",
            "query_archive_extraction",
            "query_package_installation",
            "query_web_upload_activity",
        ],
    },
    "data_exfiltration": {
        "description": "Investigate sensitive discovery, credential access, collection, staging and outbound transfer, including HTTPS and DNS channels.",
        "recommended_tools": [
            "query_discovery_commands",
            "query_sensitive_file_access",
            "query_archive_activity",
            "query_staging_directory_activity",
            "query_data_transfer",
            "query_process_network_bytes",
            "query_http_activity",
            "query_dns_payload_activity",
            "query_data_transfer_baseline",
        ],
    },
    "ransomware": {
        "description": "Investigate bulk file impact, probable encryption, recovery inhibition, service disruption and ransom-note creation.",
        "recommended_tools": ["query_bulk_file_modification", "query_file_content_change", "query_file_rename_patterns", "query_backup_destruction", "query_snapshot_activity", "query_service_disruption", "query_ransom_note_activity", "query_destructive_commands", "query_ransomware_baseline"],
    },
    "cross_host": {
        "description": "Investigate an evidence-grounded candidate host for file propagation, remote login and target execution.",
        "recommended_tools": ["query_file_transfer_across_hosts", "query_hash_presence", "query_internal_connections", "query_remote_login_sessions", "query_account_activity_across_hosts", "query_shared_endpoint_hosts", "query_host_asset_context"],
    },
}


def activation_catalog(state: InvestigationState) -> list[dict[str, Any]]:
    return [
        {"scenario": name, **config}
        for name, config in SCENARIO_CATALOG.items()
        if name not in state.active_scenarios
    ]


def activate_scenario(state: InvestigationState, scenario: str, reason_refs: list[str]) -> bool:
    """Activate a reviewed scenario template; the model cannot invent its schema."""
    if scenario in state.active_scenarios:
        return False
    if scenario not in SCENARIO_CATALOG:
        raise ValueError(f"Unknown scenario activation: {scenario}")
    known_refs = (
        {item.evidence_id for item in state.evidence}
        | {item.fact_id for item in state.facts}
        | {item.finding_id for item in state.findings}
    )
    missing = set(reason_refs) - known_refs
    if not reason_refs or missing:
        raise ValueError(f"Scenario activation requires existing reason refs; missing={sorted(missing)}")

    if scenario == "c2":
        for gap in state.evidence_gaps:
            if gap.gap_id in {"gap-process-chain", "gap-network", "gap-remote-command", "gap-persistence", "gap-counter"}:
                gap.status = "open"
                gap.resolution = "none"
                gap.limitations = [item for item in gap.limitations if "non-C2 scenario profile" not in item]
        for role in state.evidence_roles:
            if role.role_id != "role-execution":
                role.status = "unsatisfied"
    elif scenario == "file_provenance":
        hypothesis_id = "hyp-file-provenance-001"
        origin_types = ["file_create", "file_download", "file_transfer", "archive_extraction", "package_install", "web_upload"]
        state.hypotheses.append(Hypothesis(
            hypothesis_id=hypothesis_id,
            hypothesis_type="file_provenance",
            statement="The investigated file has an origin path that can be established from independent host or delivery telemetry.",
            supporting_refs=list(dict.fromkeys(reason_refs)),
        ))
        state.evidence_roles.append(EvidenceRole(
            role_id="role-file-provenance",
            role_type="provenance",
            question="How did the investigated file arrive on the host?",
            hypothesis_refs=[hypothesis_id],
            required_evidence_types=origin_types,
            requirement_mode="any",
            required_for_verdict=True,
        ))
        state.evidence_gaps.append(EvidenceGap(
            gap_id="gap-file-origin",
            gap_type="file_origin",
            question="Which independently observed event created or delivered the investigated file?",
            reason="File origin is needed to distinguish package installation, operator transfer, exploitation and external delivery.",
            required_evidence_types=origin_types,
            requirement_mode="any",
            recommended_tools=list(SCENARIO_CATALOG[scenario]["recommended_tools"]),
            priority="high",
            required_for_closure=True,
        ))
    elif scenario == "data_exfiltration":
        hypothesis_id = "hyp-data-exfiltration-001"
        state.hypotheses.append(Hypothesis(
            hypothesis_id=hypothesis_id,
            hypothesis_type="data_exfiltration",
            statement="The investigated file or its process tree may discover, collect, stage and transfer sensitive data outside its approved operational purpose.",
            supporting_refs=list(dict.fromkeys(reason_refs)),
        ))
        state.evidence_roles.extend([
            EvidenceRole(role_id="role-sensitive-access", role_type="behavior", question="Did the process tree successfully read sensitive data?", hypothesis_refs=[hypothesis_id], required_evidence_types=["sensitive_file_access"], required_for_verdict=True),
            EvidenceRole(role_id="role-data-staging", role_type="behavior", question="Was sensitive data collected into an archive or staging object?", hypothesis_refs=[hypothesis_id], required_evidence_types=["archive_create", "archive_member", "staging_file"], requirement_mode="any", required_for_verdict=True),
            EvidenceRole(role_id="role-data-transfer", role_type="impact", question="Was staged data transferred through HTTPS, another network protocol, or DNS?", hypothesis_refs=[hypothesis_id], required_evidence_types=["network_transfer", "http_upload", "dns_query"], requirement_mode="any", required_for_verdict=True),
            EvidenceRole(role_id="role-transfer-counter", role_type="counter_evidence", question="Does an approved backup or synchronization baseline explain the transfer?", hypothesis_refs=[hypothesis_id], required_evidence_types=["transfer_baseline"], required_for_verdict=True),
        ])
        state.evidence_gaps.extend([
            EvidenceGap(gap_id="gap-sensitive-discovery", gap_type="sensitive_discovery", question="Did the process enumerate sensitive files, accounts, mounts or data stores?", reason="Discovery can explain how later sensitive objects were selected but does not prove collection.", required_evidence_types=["discovery_command"], recommended_tools=["query_discovery_commands"], priority="medium", required_for_closure=False),
            EvidenceGap(gap_id="gap-sensitive-access", gap_type="sensitive_access", question="Which sensitive files were successfully read by the investigated process tree?", reason="Successful sensitive access is required before data theft can be attributed.", required_evidence_types=["sensitive_file_access"], recommended_tools=["query_sensitive_file_access"], priority="critical"),
            EvidenceGap(gap_id="gap-data-staging", gap_type="data_staging", question="Was sensitive input collected into an archive or staging object?", reason="Staging connects sensitive access to a transferable data object.", required_evidence_types=["archive_create", "archive_member", "staging_file"], requirement_mode="any", recommended_tools=["query_archive_activity", "query_staging_directory_activity"], priority="high"),
            EvidenceGap(gap_id="gap-data-transfer", gap_type="data_transfer", question="Did the process tree successfully transfer data outside the host?", reason="A successful transfer is needed to distinguish collection from actual exfiltration.", required_evidence_types=["network_transfer", "http_upload", "dns_query"], requirement_mode="any", recommended_tools=["query_data_transfer", "query_process_network_bytes", "query_http_activity", "query_dns_payload_activity"], priority="critical"),
            EvidenceGap(gap_id="gap-dns-tunnel", gap_type="dns_tunnel", question="Does process-attributed DNS activity exhibit an encoded tunnel pattern?", reason="DNS can provide an alternative covert transfer channel.", required_evidence_types=["dns_query"], recommended_tools=["query_dns_payload_activity"], priority="medium", required_for_closure=False),
            EvidenceGap(gap_id="gap-transfer-counter", gap_type="transfer_counter", question="Is the process and destination covered by an approved transfer baseline?", reason="Legitimate backup and synchronization behavior must be evaluated before a malicious verdict.", required_evidence_types=["transfer_baseline"], recommended_tools=["query_data_transfer_baseline"], priority="high"),
            EvidenceGap(gap_id="gap-exfiltration-chain", gap_type="exfiltration", question="Do sensitive access, staging and transfer form one attributed and ordered behavior chain?", reason="A confirmed exfiltration verdict requires a complete evidence-grounded chain and counter-evidence review.", required_evidence_types=["sensitive_file_access", "archive_create", "archive_member", "transfer_baseline"], recommended_tools=["query_sensitive_file_access", "query_archive_activity", "query_data_transfer", "query_dns_payload_activity", "query_data_transfer_baseline"], priority="critical"),
        ])
    elif scenario == "ransomware":
        hypothesis_id = "hyp-ransomware-001"
        state.hypotheses.append(Hypothesis(hypothesis_id=hypothesis_id, hypothesis_type="ransomware", statement="The investigated file or process tree may have encrypted or destructively modified files and inhibited recovery.", supporting_refs=list(dict.fromkeys(reason_refs))))
        state.evidence_roles.extend([
            EvidenceRole(role_id="role-bulk-impact", role_type="impact", question="Did the process cause high-rate, broad file changes?", hypothesis_refs=[hypothesis_id], required_evidence_types=["bulk_file_metric"], required_for_verdict=True),
            EvidenceRole(role_id="role-file-encryption", role_type="behavior", question="Do content and rename changes support actual encryption?", hypothesis_refs=[hypothesis_id], required_evidence_types=["file_content_change", "file_rename_pattern"], required_for_verdict=True),
            EvidenceRole(role_id="role-recovery-impact", role_type="impact", question="Were backups, snapshots or critical services successfully disrupted?", hypothesis_refs=[hypothesis_id], required_evidence_types=["backup_destruction", "snapshot_activity", "service_disruption", "destructive_command"], requirement_mode="any", required_for_verdict=True),
            EvidenceRole(role_id="role-ransom-marker", role_type="behavior", question="Was a ransom note created broadly?", hypothesis_refs=[hypothesis_id], required_evidence_types=["ransom_note"], required_for_verdict=False),
            EvidenceRole(role_id="role-ransom-counter", role_type="counter_evidence", question="Does approved batch processing explain the behavior?", hypothesis_refs=[hypothesis_id], required_evidence_types=["authorized_batch_baseline"], required_for_verdict=True),
        ])
        state.evidence_gaps.extend([
            EvidenceGap(gap_id="gap-bulk-file-impact", gap_type="bulk_file_impact", question="How many files and directories were actually modified and at what rate?", reason="Broad high-rate impact distinguishes ransomware from isolated writes.", required_evidence_types=["bulk_file_metric"], recommended_tools=["query_bulk_file_modification"], priority="critical"),
            EvidenceGap(gap_id="gap-file-encryption", gap_type="file_encryption", question="Did file contents, entropy, headers and extensions change consistently with encryption?", reason="Encryption capability or a rename alone does not prove file encryption.", required_evidence_types=["file_content_change", "file_rename_pattern"], recommended_tools=["query_file_content_change", "query_file_rename_patterns"], priority="critical"),
            EvidenceGap(gap_id="gap-recovery-inhibition", gap_type="recovery_inhibition", question="Were backups or snapshots successfully destroyed or disabled?", reason="Successful recovery inhibition increases impact and confidence.", required_evidence_types=["backup_destruction", "snapshot_activity", "destructive_command"], requirement_mode="any", recommended_tools=["query_backup_destruction", "query_snapshot_activity", "query_destructive_commands"], priority="high"),
            EvidenceGap(gap_id="gap-service-disruption", gap_type="service_disruption", question="Were business or security services actually stopped?", reason="Service disruption is impact evidence, not proof by command text alone.", required_evidence_types=["service_disruption"], recommended_tools=["query_service_disruption"], priority="medium", required_for_closure=False),
            EvidenceGap(gap_id="gap-ransom-note", gap_type="ransom_note", question="Were ransom notes created across affected locations?", reason="A ransom marker strengthens attribution but is not mandatory when destructive encryption is directly proven.", required_evidence_types=["ransom_note"], recommended_tools=["query_ransom_note_activity"], priority="high", required_for_closure=False),
            EvidenceGap(gap_id="gap-ransomware-counter", gap_type="ransomware_counter", question="Is there an approved encryption, deployment, compression or log-rotation explanation?", reason="Legitimate high-volume jobs must be checked before a ransomware verdict.", required_evidence_types=["authorized_batch_baseline"], recommended_tools=["query_ransomware_baseline"], priority="high"),
            EvidenceGap(gap_id="gap-ransomware-chain", gap_type="ransomware_chain", question="Do execution, broad impact, actual encryption and destructive effects form one process-attributed chain?", reason="The final ransomware conclusion requires an evidence-grounded impact chain.", required_evidence_types=["bulk_file_metric", "file_content_change", "file_rename_pattern", "authorized_batch_baseline"], requirement_mode="any", recommended_tools=["query_bulk_file_modification", "query_file_content_change", "query_file_rename_patterns", "query_backup_destruction", "query_ransom_note_activity", "query_ransomware_baseline"], priority="critical"),
        ])
    elif scenario == "cross_host":
        hypothesis_id = "hyp-cross-host-001"
        state.hypotheses.append(Hypothesis(hypothesis_id=hypothesis_id, hypothesis_type="cross_host_propagation", statement="The investigated file or access path may have propagated to another host.", supporting_refs=list(dict.fromkeys(reason_refs))))
        state.evidence_roles.extend([
            EvidenceRole(role_id="role-cross-host-lead", role_type="scope", question="Which evidence directly identifies a candidate host?", hypothesis_refs=[hypothesis_id], required_evidence_types=["file_transfer_cross_host", "internal_connection", "shared_endpoint_host"], requirement_mode="any", required_for_verdict=True),
            EvidenceRole(role_id="role-cross-host-confirmation", role_type="impact", question="Did the same hash arrive and execute after a related remote session?", hypothesis_refs=[hypothesis_id], required_evidence_types=["hash_presence", "remote_login_session"], required_for_verdict=True),
            EvidenceRole(role_id="role-cross-host-counter", role_type="counter_evidence", question="Does approved asset and deployment context explain multi-host presence?", hypothesis_refs=[hypothesis_id], required_evidence_types=["host_asset_context"], required_for_verdict=True),
        ])
        state.evidence_gaps.extend([
            EvidenceGap(gap_id="gap-cross-host-lead", gap_type="cross_host_lead", question="Which directly observed event points from the current host to a candidate host?", reason="Scope expansion requires a concrete host reference in existing evidence.", required_evidence_types=["file_transfer_cross_host", "internal_connection", "shared_endpoint_host"], requirement_mode="any", recommended_tools=["query_file_transfer_across_hosts", "query_internal_connections", "query_shared_endpoint_hosts"], priority="critical"),
            EvidenceGap(gap_id="gap-cross-host-confirmation", gap_type="cross_host_confirmation", question="Is the investigated hash present or executed on the approved candidate host after related access?", reason="Target execution cannot be inferred from a source-side transfer alone.", required_evidence_types=["hash_presence", "remote_login_session"], recommended_tools=["query_hash_presence", "query_remote_login_sessions", "query_account_activity_across_hosts"], priority="critical"),
            EvidenceGap(gap_id="gap-cross-host-counter", gap_type="cross_host_counter", question="Is the multi-host activity an approved software deployment?", reason="Legitimate fleet deployment must be tested as counter-evidence.", required_evidence_types=["host_asset_context"], recommended_tools=["query_host_asset_context"], priority="high"),
        ])
    state.active_scenarios.append(scenario)
    return True


def add_interpretation(state: InvestigationState, proposal: dict[str, Any], model: str) -> str:
    fact_ids = {item.fact_id for item in state.facts}
    finding_ids = {item.finding_id for item in state.findings}
    supporting_facts = [str(ref) for ref in proposal.get("supporting_fact_refs") or []]
    supporting_findings = [str(ref) for ref in proposal.get("supporting_finding_refs") or []]
    contradicting = [str(ref) for ref in proposal.get("contradicting_refs") or []]
    known = fact_ids | finding_ids
    unresolved = (set(supporting_facts) - fact_ids) | (set(supporting_findings) - finding_ids) | (set(contradicting) - known)
    statement = str(proposal.get("statement") or "").strip()
    if unresolved or not statement or not (supporting_facts or supporting_findings):
        raise ValueError(f"Interpretation requires a statement and resolvable Fact/Finding refs; unresolved={sorted(unresolved)}")
    confidence = float(proposal.get("confidence", 0.5))
    if not 0 <= confidence <= 1:
        raise ValueError("Interpretation confidence must be between 0 and 1")
    fingerprint = (statement, tuple(sorted(supporting_facts)), tuple(sorted(supporting_findings)), tuple(sorted(contradicting)))
    for existing in state.interpretations:
        existing_fingerprint = (existing.statement, tuple(sorted(existing.supporting_fact_refs)), tuple(sorted(existing.supporting_finding_refs)), tuple(sorted(existing.contradicting_refs)))
        if existing_fingerprint == fingerprint:
            return existing.interpretation_id
    interpretation_id = f"interpretation-{len(state.interpretations)+1:03d}"
    state.interpretations.append(Interpretation(
        interpretation_id=interpretation_id,
        interpretation_type=str(proposal.get("interpretation_type") or "case_assessment"),
        statement=statement,
        supporting_fact_refs=supporting_facts,
        supporting_finding_refs=supporting_findings,
        contradicting_refs=contradicting,
        confidence=confidence,
        model=model,
    ))
    return interpretation_id
