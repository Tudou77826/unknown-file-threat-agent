from __future__ import annotations

from collections import defaultdict
from math import log2
from statistics import median

from .models import Fact, FactFindingBundle, Finding, InvestigationState, Relation


def _ev(state: InvestigationState, domain: str, evidence_refs: list[str] | None = None):
    """Return evidence explicitly authorized by the AnalysisRequest."""
    allowed = set(evidence_refs) if evidence_refs is not None else None
    return [
        e for e in state.evidence
        if e.domain == domain
        and e.status.value == "available"
        and (allowed is None or e.evidence_id in allowed)
    ]


def verify_execution(state: InvestigationState, evidence_refs: list[str] | None = None, parameters: dict | None = None) -> FactFindingBundle:
    facts, relations = [], []
    for e in _ev(state, "process", evidence_refs):
        if e.evidence_type != "process_exec":
            continue
        file_ref = e.data.get("file_ref") or next((x for x in e.subject_refs if x.startswith("file:")), None)
        proc_ref = e.data.get("process_ref") or next((x for x in e.subject_refs if x.startswith("process:")), None)
        if not file_ref or not proc_ref:
            continue
        facts.append(Fact(fact_id=f"fact-exec-{len(facts)+1:03d}", fact_type="file_executed", statement=f"Unknown file executed as process {proc_ref}", subject_refs=[file_ref, proc_ref], evidence_refs=[e.evidence_id], observed_at=e.observed_at, verification_method="ExecutionAnalyzer/1.0"))
        relations.append(Relation(relation_id=f"rel-exec-{len(relations)+1:03d}", relation_type="executed_as", source_entity_ref=file_ref, target_entity_ref=proc_ref, evidence_refs=[e.evidence_id], confidence="confirmed", observed_at=e.observed_at))
    return FactFindingBundle(facts=facts, relations=relations, limitations=[] if facts else ["No independent process execution event was available"])


def analyze_process_chain(state: InvestigationState, evidence_refs: list[str] | None = None, parameters: dict | None = None) -> FactFindingBundle:
    facts, findings, relations = [], [], []
    for e in _ev(state, "process", evidence_refs):
        if e.evidence_type != "process_parent_relation":
            continue
        parent, child = e.data.get("parent_ref"), e.data.get("child_ref")
        if not parent or not child:
            continue
        relations.append(Relation(relation_id=f"rel-spawn-{len(relations)+1:03d}", relation_type="spawned", source_entity_ref=parent, target_entity_ref=child, evidence_refs=[e.evidence_id], confidence="confirmed", observed_at=e.observed_at))
    if relations:
        facts.append(Fact(fact_id="fact-process-chain-001", fact_type="process_chain_verified", statement=f"Verified {len(relations)} parent-child process relations", evidence_refs=[x for r in relations for x in r.evidence_refs], verification_method="ProcessChainAnalyzer/1.0"))
    return FactFindingBundle(facts=facts, findings=findings, relations=relations, limitations=[] if relations else ["No independent parent-child events were available"])


def analyze_network(state: InvestigationState, evidence_refs: list[str] | None = None, parameters: dict | None = None) -> FactFindingBundle:
    events = [e for e in _ev(state, "network", evidence_refs) if e.evidence_type == "network_connection"]
    facts, findings, relations = [], [], []
    grouped = defaultdict(list)
    for e in events:
        key = (e.data.get("process_ref"), e.data.get("remote_ip"), e.data.get("remote_port"))
        grouped[key].append(e)
    for (proc, ip, port), rows in grouped.items():
        refs = [e.evidence_id for e in rows]
        facts.append(Fact(fact_id=f"fact-net-{len(facts)+1:03d}", fact_type="external_connection_observed", statement=f"Process {proc} connected to {ip}:{port} {len(rows)} time(s)", subject_refs=[x for x in [proc, f"endpoint:{ip}:{port}"] if x], evidence_refs=refs, observed_at=rows[0].observed_at, verification_method="NetworkAnalyzer/1.0"))
        if proc and ip:
            relations.append(Relation(relation_id=f"rel-net-{len(relations)+1:03d}", relation_type="connected_to", source_entity_ref=proc, target_entity_ref=f"endpoint:{ip}:{port}", evidence_refs=refs, confidence="confirmed", observed_at=rows[0].observed_at))
        times = sorted(e.observed_at.timestamp() for e in rows if e.observed_at)
        if len(times) >= 4:
            intervals = [b-a for a, b in zip(times, times[1:])]
            center = median(intervals)
            spread = max(abs(x-center) for x in intervals)
            if center > 0 and spread <= max(10, center * 0.2):
                findings.append(Finding(finding_id=f"finding-periodic-{len(findings)+1:03d}", finding_type="periodic_external_connection", statement=f"Connections to {ip}:{port} recur approximately every {center:.0f} seconds", severity="high", subject_refs=[proc] if proc else [], evidence_refs=refs, supporting_fact_refs=[facts[-1].fact_id], analyzer="NetworkPeriodicityAnalyzer", confidence=0.9, limitations=["Periodicity alone does not prove C2"] ))
    return FactFindingBundle(facts=facts, findings=findings, relations=relations, limitations=[] if events else ["No process-attributed network events were available"])


def analyze_remote_command(state: InvestigationState, evidence_refs: list[str] | None = None, parameters: dict | None = None) -> FactFindingBundle:
    connections = [e for e in _ev(state, "network", evidence_refs) if e.evidence_type == "network_connection"]
    socket_events = [e for e in _ev(state, "network", evidence_refs) if e.evidence_type == "socket_io"]
    relations = [e for e in _ev(state, "process", evidence_refs) if e.evidence_type == "process_parent_relation"]
    executions = [e for e in _ev(state, "process", evidence_refs) if e.evidence_type == "child_process_exec"]
    findings = []
    processed_controllers = set()
    for connection in connections:
        controller = connection.data.get("process_ref")
        if not controller or controller in processed_controllers:
            continue
        processed_controllers.add(controller)
        controller_connections = [e for e in connections if e.data.get("process_ref") == controller]
        io_rows = [e for e in socket_events if e.data.get("process_ref") == controller]
        inbound = [e for e in io_rows if e.data.get("direction") == "inbound" and int(e.data.get("bytes", 0)) > 0]
        outbound = [e for e in io_rows if e.data.get("direction") == "outbound" and int(e.data.get("bytes", 0)) > 0]
        child_refs = {
            e.data.get("child_ref") for e in relations
            if e.data.get("parent_ref") == controller and e.data.get("child_ref")
        }
        child_execs = [
            e for e in executions
            if e.data.get("process_ref") in child_refs and e.data.get("cmdline")
        ]
        correlated_execs = [
            execution for execution in child_execs
            if execution.observed_at
            and any(row.observed_at and row.observed_at <= execution.observed_at for row in inbound)
            and any(row.observed_at and execution.observed_at <= row.observed_at for row in outbound)
        ]
        if not inbound or not outbound or not correlated_execs:
            continue
        refs = sorted({
            *(e.evidence_id for e in controller_connections),
            *(e.evidence_id for e in inbound),
            *(e.evidence_id for e in outbound),
            *(e.evidence_id for e in correlated_execs),
            *(e.evidence_id for e in relations if e.data.get("child_ref") in child_refs),
        })
        commands = [str(e.data.get("cmdline")) for e in correlated_execs]
        findings.append(Finding(
            finding_id=f"finding-remote-command-{len(findings)+1:03d}",
            finding_type="remote_command_execution",
            statement=f"Inbound socket data was followed by child command execution and outbound data: {commands}",
            severity="critical",
            subject_refs=[controller] if controller else [],
            evidence_refs=refs,
            analyzer="RemoteCommandCorrelationAnalyzer",
            confidence=0.96,
            limitations=["Correlation is based on process identity, ancestry and event order; payload content is not required"],
        ))
    return FactFindingBundle(
        findings=findings,
        limitations=[] if findings else ["No inbound-command-outbound process sequence was established"],
    )


def analyze_persistence(state: InvestigationState, evidence_refs: list[str] | None = None, parameters: dict | None = None) -> FactFindingBundle:
    facts, findings, relations = [], [], []
    grouped = defaultdict(list)
    for e in _ev(state, "persistence", evidence_refs):
        if e.evidence_type == "systemd_event":
            grouped[e.data.get("unit") or e.data.get("mechanism", "unknown")].append(e)
    for mechanism, rows in grouped.items():
        target = next((e.data.get("exec_file_ref") or e.data.get("target_file_ref") for e in rows if e.data.get("exec_file_ref") or e.data.get("target_file_ref")), None)
        actions = {e.data.get("action") for e in rows}
        activated = bool(target and {"unit_write", "enable", "start"} <= actions)
        refs = [e.evidence_id for e in rows]
        facts.append(Fact(fact_id=f"fact-persist-{len(facts)+1:03d}", fact_type="persistence_configuration_observed", statement=f"{mechanism} references the unknown file; actions={sorted(x for x in actions if x)}", subject_refs=[target] if target else [], evidence_refs=refs, observed_at=rows[0].observed_at, verification_method="SystemdPersistenceAnalyzer/1.0"))
        findings.append(Finding(finding_id=f"finding-persist-{len(findings)+1:03d}", finding_type="active_persistence" if activated else "persistence_attempt", statement=f"Unknown file is referenced by {mechanism} persistence", severity="high" if activated else "medium", subject_refs=[target] if target else [], evidence_refs=refs, supporting_fact_refs=[facts[-1].fact_id], analyzer="SystemdPersistenceAnalyzer", confidence=0.94 if activated else 0.7))
        if target:
            relations.append(Relation(relation_id=f"rel-persist-{len(relations)+1:03d}", relation_type="persisted_by", source_entity_ref=target, target_entity_ref=f"persistence:{mechanism}", evidence_refs=refs, confidence="confirmed" if activated else "supported", observed_at=rows[0].observed_at))
    return FactFindingBundle(facts=facts, findings=findings, relations=relations, limitations=[] if facts else ["No persistence configuration evidence was available"])


def analyze_reputation(state: InvestigationState, evidence_refs: list[str] | None = None, parameters: dict | None = None) -> FactFindingBundle:
    facts, findings = [], []
    for e in _ev(state, "reputation", evidence_refs):
        if e.evidence_type == "package_provenance" and e.data.get("owns_file") and e.data.get("signature_valid") and e.data.get("repository_trusted"):
            facts.append(Fact(fact_id="fact-trusted-package-001", fact_type="trusted_package_provenance", statement="File hash and path match a trusted signed package", evidence_refs=[e.evidence_id], verification_method="CounterEvidenceAnalyzer/1.0"))
        if e.evidence_type == "approved_endpoint" and e.data.get("approved"):
            facts.append(Fact(fact_id="fact-known-endpoint-001", fact_type="known_service_endpoint", statement="Observed remote endpoint is an approved service endpoint", evidence_refs=[e.evidence_id], verification_method="CounterEvidenceAnalyzer/1.0"))
    if {x.fact_type for x in facts} >= {"trusted_package_provenance", "known_service_endpoint"}:
        findings.append(Finding(finding_id="finding-benign-explanation-001", finding_type="legitimate_software_explanation", statement="Trusted provenance and approved service behavior provide a benign explanation", severity="info", evidence_refs=sorted({ref for fact in facts for ref in fact.evidence_refs}), supporting_fact_refs=[x.fact_id for x in facts], analyzer="CounterEvidenceAnalyzer", confidence=0.95))
    return FactFindingBundle(facts=facts, findings=findings, limitations=[] if facts else ["No trusted provenance or approved baseline was found"])


def analyze_file_provenance(state: InvestigationState, evidence_refs: list[str] | None = None, parameters: dict | None = None) -> FactFindingBundle:
    """Derive how the investigated file arrived without treating origin as malicious by itself."""
    events = [
        e for e in _ev(state, "file", evidence_refs)
        if e.evidence_type in {"file_create", "file_download", "file_transfer", "archive_extraction", "package_install", "web_upload"}
    ]
    facts, findings, relations = [], [], []
    for event in events:
        data = event.data
        file_ref = data.get("file_ref") or data.get("extracted_file_ref") or next(
            (ref for ref in event.subject_refs if ref.startswith("file:")), None
        )
        if not file_ref:
            continue
        fact_type = {
            "file_create": "file_created",
            "file_download": "file_downloaded",
            "file_transfer": "file_transferred",
            "archive_extraction": "file_extracted_from_archive",
            "package_install": "file_installed_by_package",
            "web_upload": "file_uploaded_through_web_service",
        }[event.evidence_type]
        source_ref = None
        relation_type = "created"
        statement = f"The investigated file {file_ref} has an independently observed {event.evidence_type} origin event"

        if event.evidence_type == "file_create":
            source_ref = data.get("creator_process_ref") or data.get("process_ref")
            relation_type = "created"
        elif event.evidence_type == "file_download":
            source_ref = data.get("endpoint_ref")
            if not source_ref and data.get("remote_ip"):
                source_ref = f"endpoint:{data['remote_ip']}:{data.get('remote_port', 0)}"
            relation_type = "delivered"
            statement = f"The investigated file was downloaded from {data.get('url') or source_ref or 'an external source'}"
        elif event.evidence_type == "file_transfer":
            source_ref = data.get("session_ref") or data.get("source_host_ref")
            relation_type = "transferred"
            statement = f"The investigated file was transferred using {data.get('method', 'a remote file-transfer mechanism')}"
        elif event.evidence_type == "archive_extraction":
            source_ref = data.get("archive_ref")
            relation_type = "extracted"
            statement = f"The investigated file was extracted from {source_ref or 'an archive'}"
        elif event.evidence_type == "package_install":
            package_name = str(data.get("package") or "unknown")
            source_ref = data.get("package_ref") or f"package:{package_name}"
            relation_type = "installed"
            statement = f"The investigated file was installed by package {package_name}"
        elif event.evidence_type == "web_upload":
            source_ref = data.get("web_process_ref") or data.get("session_ref")
            relation_type = "uploaded"
            statement = "The investigated file was written through a web-service upload path"

        fact = Fact(
            fact_id=f"fact-origin-{len(facts)+1:03d}",
            fact_type=fact_type,
            statement=statement,
            subject_refs=[ref for ref in (source_ref, file_ref) if ref],
            evidence_refs=[event.evidence_id],
            observed_at=event.observed_at,
            verification_method="FileProvenanceAnalyzer/1.0",
        )
        facts.append(fact)
        if source_ref:
            relations.append(Relation(
                relation_id=f"rel-origin-{len(relations)+1:03d}",
                relation_type=relation_type,
                source_entity_ref=source_ref,
                target_entity_ref=file_ref,
                evidence_refs=[event.evidence_id],
                confidence="confirmed",
                observed_at=event.observed_at,
            ))
        if event.evidence_type == "package_install" and data.get("signature_valid") and data.get("repository_trusted"):
            findings.append(Finding(
                finding_id=f"finding-origin-package-{len(findings)+1:03d}",
                finding_type="trusted_package_installation",
                statement=f"Package installation provides a trusted origin for {file_ref}",
                severity="info",
                subject_refs=[file_ref],
                evidence_refs=[event.evidence_id],
                supporting_fact_refs=[fact.fact_id],
                analyzer="FileProvenanceAnalyzer",
                confidence=0.95,
            ))
    return FactFindingBundle(
        facts=facts,
        findings=findings,
        relations=relations,
        limitations=[] if facts else ["No independently observed file-origin event was available"],
    )


def analyze_sensitive_discovery(state: InvestigationState, evidence_refs: list[str] | None = None, parameters: dict | None = None) -> FactFindingBundle:
    events = [e for e in _ev(state, "process", evidence_refs) if e.evidence_type == "discovery_command"]
    facts, findings = [], []
    for event in events:
        if not event.data.get("success", True):
            continue
        process_ref = event.data.get("process_ref")
        fact = Fact(
            fact_id=f"fact-discovery-{len(facts)+1:03d}", fact_type="sensitive_discovery_observed",
            statement=f"Process {process_ref} executed discovery command: {event.data.get('cmdline', 'unknown')}",
            subject_refs=[process_ref] if process_ref else [], evidence_refs=[event.evidence_id],
            observed_at=event.observed_at, verification_method="SensitiveDiscoveryAnalyzer/1.0",
        )
        facts.append(fact)
        if event.data.get("sensitive_target") or int(event.data.get("matched_objects", 0)) >= 5:
            findings.append(Finding(
                finding_id=f"finding-discovery-{len(findings)+1:03d}", finding_type="sensitive_data_discovery",
                statement="The process enumerated sensitive data locations or multiple sensitive objects",
                severity="medium", subject_refs=[process_ref] if process_ref else [], evidence_refs=[event.evidence_id],
                supporting_fact_refs=[fact.fact_id], analyzer="SensitiveDiscoveryAnalyzer", confidence=0.82,
                limitations=["Discovery does not prove that data was read or transferred"],
            ))
    return FactFindingBundle(facts=facts, findings=findings, limitations=[] if events else ["No scoped discovery-command evidence was available"])


def analyze_credential_access(state: InvestigationState, evidence_refs: list[str] | None = None, parameters: dict | None = None) -> FactFindingBundle:
    events = [e for e in _ev(state, "file", evidence_refs) if e.evidence_type == "sensitive_file_access"]
    facts, findings, relations = [], [], []
    for event in events:
        if not event.data.get("success") or event.data.get("operation") not in {"read", "open_read", "mmap_read", "copy"}:
            continue
        process_ref = event.data.get("process_ref")
        file_ref = event.data.get("file_ref") or next((ref for ref in event.subject_refs if ref.startswith("file:")), None)
        if not process_ref or not file_ref:
            continue
        fact = Fact(
            fact_id=f"fact-sensitive-read-{len(facts)+1:03d}", fact_type="sensitive_file_read",
            statement=f"Process {process_ref} successfully read sensitive object {file_ref}",
            subject_refs=[process_ref, file_ref], evidence_refs=[event.evidence_id], observed_at=event.observed_at,
            verification_method="CredentialAccessAnalyzer/1.0",
        )
        facts.append(fact)
        relations.append(Relation(
            relation_id=f"rel-sensitive-read-{len(relations)+1:03d}", relation_type="read",
            source_entity_ref=process_ref, target_entity_ref=file_ref, evidence_refs=[event.evidence_id],
            confidence="confirmed", observed_at=event.observed_at,
        ))
        category = str(event.data.get("sensitivity") or "sensitive_data")
        findings.append(Finding(
            finding_id=f"finding-sensitive-read-{len(findings)+1:03d}",
            finding_type="credential_access" if category in {"credential", "private_key", "token", "cookie"} else "sensitive_data_access",
            statement=f"The investigated process tree accessed {category}: {event.data.get('path') or file_ref}",
            severity="high", subject_refs=[process_ref, file_ref], evidence_refs=[event.evidence_id],
            supporting_fact_refs=[fact.fact_id], analyzer="CredentialAccessAnalyzer", confidence=0.94,
            limitations=["Sensitive access alone does not prove collection or exfiltration"],
        ))
    return FactFindingBundle(facts=facts, findings=findings, relations=relations, limitations=[] if facts else ["No successful sensitive-file read was established"])


def analyze_data_staging(state: InvestigationState, evidence_refs: list[str] | None = None, parameters: dict | None = None) -> FactFindingBundle:
    creates = [e for e in _ev(state, "file", evidence_refs) if e.evidence_type == "archive_create"]
    members = [e for e in _ev(state, "file", evidence_refs) if e.evidence_type == "archive_member" and e.data.get("sensitive")]
    staging_files = [e for e in _ev(state, "file", evidence_refs) if e.evidence_type == "staging_file" and e.data.get("sensitive_source_refs")]
    facts, findings, relations = [], [], []
    for create in creates:
        archive_ref = create.data.get("archive_ref")
        process_ref = create.data.get("process_ref")
        rows = [item for item in members if item.data.get("archive_ref") == archive_ref]
        if not archive_ref or not process_ref or not rows:
            continue
        refs = [create.evidence_id, *(item.evidence_id for item in rows)]
        fact = Fact(
            fact_id=f"fact-staging-{len(facts)+1:03d}", fact_type="sensitive_archive_created",
            statement=f"Process {process_ref} created {archive_ref} containing {len(rows)} sensitive input object(s)",
            subject_refs=[process_ref, archive_ref], evidence_refs=refs, observed_at=create.observed_at,
            verification_method="DataStagingAnalyzer/1.0",
        )
        facts.append(fact)
        relations.append(Relation(
            relation_id=f"rel-staging-create-{len(relations)+1:03d}", relation_type="created",
            source_entity_ref=process_ref, target_entity_ref=archive_ref, evidence_refs=[create.evidence_id],
            confidence="confirmed", observed_at=create.observed_at,
        ))
        for member in rows:
            input_ref = member.data.get("input_file_ref")
            if input_ref:
                relations.append(Relation(
                    relation_id=f"rel-staging-member-{len(relations)+1:03d}", relation_type="collected_into",
                    source_entity_ref=input_ref, target_entity_ref=archive_ref, evidence_refs=[member.evidence_id],
                    confidence="confirmed", observed_at=member.observed_at,
                ))
        findings.append(Finding(
            finding_id=f"finding-staging-{len(findings)+1:03d}", finding_type="sensitive_data_staging",
            statement=f"Sensitive data was collected into archive {archive_ref}", severity="high",
            subject_refs=[process_ref, archive_ref], evidence_refs=refs, supporting_fact_refs=[fact.fact_id],
            analyzer="DataStagingAnalyzer", confidence=0.95,
            limitations=["Staging does not prove that the archive left the host"],
        ))
    for event in staging_files:
        process_ref = event.data.get("process_ref")
        staged_ref = event.data.get("staged_file_ref")
        source_refs = [str(ref) for ref in event.data.get("sensitive_source_refs") or []]
        if not process_ref or not staged_ref:
            continue
        fact = Fact(
            fact_id=f"fact-staging-{len(facts)+1:03d}", fact_type="sensitive_staging_file_created",
            statement=f"Process {process_ref} staged {len(source_refs)} sensitive object(s) into {staged_ref}",
            subject_refs=[process_ref, staged_ref], evidence_refs=[event.evidence_id], observed_at=event.observed_at,
            verification_method="DataStagingAnalyzer/1.0",
        )
        facts.append(fact)
        findings.append(Finding(
            finding_id=f"finding-staging-{len(findings)+1:03d}", finding_type="sensitive_data_staging",
            statement=f"Sensitive data was copied into staging object {staged_ref}", severity="high",
            subject_refs=[process_ref, staged_ref], evidence_refs=[event.evidence_id], supporting_fact_refs=[fact.fact_id],
            analyzer="DataStagingAnalyzer", confidence=0.9,
            limitations=["Staging does not prove that the object left the host"],
        ))
    return FactFindingBundle(facts=facts, findings=findings, relations=relations, limitations=[] if findings else ["No archive with independently identified sensitive members was established"])


def analyze_data_transfer(state: InvestigationState, evidence_refs: list[str] | None = None, parameters: dict | None = None) -> FactFindingBundle:
    events = [e for e in _ev(state, "network", evidence_refs) if e.evidence_type in {"network_transfer", "http_upload"}]
    facts, findings, relations = [], [], []
    for event in events:
        if not event.data.get("success") or int(event.data.get("bytes_out", 0)) <= 0:
            continue
        process_ref = event.data.get("process_ref")
        endpoint_ref = event.data.get("endpoint_ref")
        if not endpoint_ref and event.data.get("remote_ip"):
            endpoint_ref = f"endpoint:{event.data['remote_ip']}:{event.data.get('remote_port', 0)}"
        if not process_ref or not endpoint_ref:
            continue
        fact = Fact(
            fact_id=f"fact-transfer-{len(facts)+1:03d}", fact_type="outbound_data_transfer",
            statement=f"Process {process_ref} successfully transferred {int(event.data.get('bytes_out', 0))} bytes to {endpoint_ref}",
            subject_refs=[process_ref, endpoint_ref], evidence_refs=[event.evidence_id], observed_at=event.observed_at,
            verification_method="DataTransferAnalyzer/1.0",
        )
        facts.append(fact)
        relations.append(Relation(
            relation_id=f"rel-transfer-{len(relations)+1:03d}", relation_type="transferred_to",
            source_entity_ref=process_ref, target_entity_ref=endpoint_ref, evidence_refs=[event.evidence_id],
            confidence="confirmed", observed_at=event.observed_at,
        ))
        if int(event.data.get("bytes_out", 0)) >= 1_000_000:
            findings.append(Finding(
                finding_id=f"finding-transfer-{len(findings)+1:03d}", finding_type="high_volume_external_transfer",
                statement=f"A process-attributed transfer sent at least one megabyte to {endpoint_ref}", severity="medium",
                subject_refs=[process_ref, endpoint_ref], evidence_refs=[event.evidence_id], supporting_fact_refs=[fact.fact_id],
                analyzer="DataTransferAnalyzer", confidence=0.9,
                limitations=["Transfer volume alone does not identify the transmitted content or prove exfiltration"],
            ))
    return FactFindingBundle(facts=facts, findings=findings, relations=relations, limitations=[] if facts else ["No successful outbound byte transfer was established"])


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = defaultdict(int)
    for char in value:
        counts[char] += 1
    return -sum((count / len(value)) * log2(count / len(value)) for count in counts.values())


def _dns_tunnel_groups(events):
    groups = defaultdict(list)
    for event in events:
        groups[(event.data.get("root_process_ref") or event.data.get("process_ref"), event.data.get("base_domain"))].append(event)
    matches = []
    for (root_ref, domain), rows in groups.items():
        labels = [str(item.data.get("encoded_label") or "") for item in rows]
        nonempty = [label for label in labels if label]
        if len(rows) < 8 or len(set(nonempty)) < 6:
            continue
        average_length = sum(map(len, nonempty)) / len(nonempty) if nonempty else 0
        average_entropy = sum(_entropy(label) for label in nonempty) / len(nonempty) if nonempty else 0
        if average_length >= 20 and average_entropy >= 3.2:
            matches.append((root_ref, domain, rows, average_length, average_entropy))
    return matches


def analyze_dns_tunneling(state: InvestigationState, evidence_refs: list[str] | None = None, parameters: dict | None = None) -> FactFindingBundle:
    events = [e for e in _ev(state, "network", evidence_refs) if e.evidence_type == "dns_query"]
    facts, findings, relations = [], [], []
    for root_ref, domain, rows, avg_len, avg_entropy in _dns_tunnel_groups(events):
        refs = [item.evidence_id for item in rows]
        endpoint_ref = f"endpoint:dns:{domain}"
        fact = Fact(
            fact_id=f"fact-dns-tunnel-{len(facts)+1:03d}", fact_type="encoded_dns_query_sequence",
            statement=f"{len(rows)} process-attributed DNS queries to {domain} used long high-entropy unique labels",
            subject_refs=[ref for ref in (root_ref, endpoint_ref) if ref], evidence_refs=refs,
            observed_at=rows[0].observed_at, verification_method="DnsTunnelAnalyzer/1.0",
        )
        facts.append(fact)
        findings.append(Finding(
            finding_id=f"finding-dns-tunnel-{len(findings)+1:03d}", finding_type="dns_tunnel_pattern",
            statement=f"DNS labels averaged {avg_len:.1f} characters and {avg_entropy:.2f} bits of entropy across {len(rows)} queries",
            severity="high", subject_refs=[ref for ref in (root_ref, endpoint_ref) if ref], evidence_refs=refs,
            supporting_fact_refs=[fact.fact_id], analyzer="DnsTunnelAnalyzer", confidence=0.91,
            limitations=["Encoded DNS behavior can have legitimate uses and requires process, data-source and baseline context"],
        ))
        if root_ref:
            relations.append(Relation(
                relation_id=f"rel-dns-{len(relations)+1:03d}", relation_type="queried",
                source_entity_ref=root_ref, target_entity_ref=endpoint_ref, evidence_refs=refs,
                confidence="confirmed", observed_at=rows[0].observed_at,
            ))
    return FactFindingBundle(facts=facts, findings=findings, relations=relations, limitations=[] if findings else ["No process-attributed DNS tunnel pattern met the deterministic thresholds"])


def _baseline_approved(baselines, endpoint_ref: str | None, root_ref: str | None) -> bool:
    return any(
        item.data.get("approved")
        and (not item.data.get("endpoint_ref") or item.data.get("endpoint_ref") == endpoint_ref)
        and (not item.data.get("root_process_ref") or item.data.get("root_process_ref") == root_ref)
        for item in baselines
    )


def _exfil_components(state, evidence_refs):
    file_events = _ev(state, "file", evidence_refs)
    network_events = _ev(state, "network", evidence_refs)
    reputation_events = _ev(state, "reputation", evidence_refs)
    accesses = [e for e in file_events if e.evidence_type == "sensitive_file_access" and e.data.get("success")]
    creates = [e for e in file_events if e.evidence_type == "archive_create"]
    members = [e for e in file_events if e.evidence_type == "archive_member" and e.data.get("sensitive")]
    transfers = [e for e in network_events if e.evidence_type in {"network_transfer", "http_upload"} and e.data.get("success")]
    dns = [e for e in network_events if e.evidence_type == "dns_query"]
    baselines = [e for e in reputation_events if e.evidence_type == "transfer_baseline"]
    return accesses, creates, members, transfers, dns, baselines


def analyze_https_exfiltration(state: InvestigationState, evidence_refs: list[str] | None = None, parameters: dict | None = None) -> FactFindingBundle:
    accesses, creates, members, transfers, _dns, baselines = _exfil_components(state, evidence_refs)
    findings, relations = [], []
    roots = {e.data.get("root_process_ref") or e.data.get("process_ref") for e in accesses}
    for root_ref in roots - {None}:
        read_rows = [e for e in accesses if (e.data.get("root_process_ref") or e.data.get("process_ref")) == root_ref]
        sensitive_refs = {e.data.get("file_ref") for e in read_rows}
        for create in [e for e in creates if (e.data.get("root_process_ref") or e.data.get("process_ref")) == root_ref]:
            archive_ref = create.data.get("archive_ref")
            member_rows = [e for e in members if e.data.get("archive_ref") == archive_ref and e.data.get("input_file_ref") in sensitive_refs]
            transfer_rows = [e for e in transfers if (e.data.get("root_process_ref") or e.data.get("process_ref")) == root_ref and e.data.get("transmitted_object_ref") == archive_ref]
            for transfer in transfer_rows:
                if not (read_rows[0].observed_at and create.observed_at and transfer.observed_at and read_rows[0].observed_at <= create.observed_at <= transfer.observed_at):
                    continue
                endpoint_ref = transfer.data.get("endpoint_ref")
                if not endpoint_ref:
                    continue
                refs = sorted({*(e.evidence_id for e in read_rows), create.evidence_id, *(e.evidence_id for e in member_rows), transfer.evidence_id, *(e.evidence_id for e in baselines)})
                if not member_rows:
                    continue
                if _baseline_approved(baselines, endpoint_ref, root_ref):
                    findings.append(Finding(
                        finding_id=f"finding-legitimate-transfer-{len(findings)+1:03d}", finding_type="legitimate_backup_explanation",
                        statement="An approved process-and-endpoint baseline explains the sensitive archive transfer",
                        severity="info", subject_refs=[root_ref, archive_ref, endpoint_ref], evidence_refs=refs,
                        analyzer="HttpsExfiltrationCorrelationAnalyzer", confidence=0.96,
                    ))
                else:
                    findings.append(Finding(
                        finding_id=f"finding-exfil-{len(findings)+1:03d}", finding_type="confirmed_data_exfiltration",
                        statement="Sensitive files were read, collected into an archive, and the same archive was successfully transferred to an unapproved external endpoint",
                        severity="critical", subject_refs=[root_ref, archive_ref, endpoint_ref], evidence_refs=refs,
                        analyzer="HttpsExfiltrationCorrelationAnalyzer", confidence=0.97,
                    ))
                relations.append(Relation(
                    relation_id=f"rel-exfil-{len(relations)+1:03d}", relation_type="exfiltrated_to",
                    source_entity_ref=archive_ref, target_entity_ref=endpoint_ref, evidence_refs=[transfer.evidence_id],
                    confidence="confirmed", observed_at=transfer.observed_at,
                ))
    return FactFindingBundle(findings=findings, relations=relations, limitations=[] if findings else ["No ordered sensitive-read, archive-member and transferred-object chain was established"])


def analyze_dns_exfiltration(state: InvestigationState, evidence_refs: list[str] | None = None, parameters: dict | None = None) -> FactFindingBundle:
    accesses, creates, members, _transfers, dns, baselines = _exfil_components(state, evidence_refs)
    findings, relations = [], []
    for root_ref, domain, rows, _avg_len, _avg_entropy in _dns_tunnel_groups(dns):
        read_rows = [e for e in accesses if (e.data.get("root_process_ref") or e.data.get("process_ref")) == root_ref]
        sensitive_refs = {e.data.get("file_ref") for e in read_rows}
        create = next((e for e in creates if (e.data.get("root_process_ref") or e.data.get("process_ref")) == root_ref), None)
        if not create:
            continue
        archive_ref = create.data.get("archive_ref")
        member_rows = [e for e in members if e.data.get("archive_ref") == archive_ref and e.data.get("input_file_ref") in sensitive_refs]
        if not read_rows or not member_rows or not any(int(e.data.get("payload_bytes", 0)) > 0 for e in rows):
            continue
        endpoint_ref = f"endpoint:dns:{domain}"
        refs = sorted({*(e.evidence_id for e in read_rows), create.evidence_id, *(e.evidence_id for e in member_rows), *(e.evidence_id for e in rows), *(e.evidence_id for e in baselines)})
        if _baseline_approved(baselines, endpoint_ref, root_ref):
            findings.append(Finding(
                finding_id=f"finding-legitimate-dns-{len(findings)+1:03d}", finding_type="legitimate_backup_explanation",
                statement="An approved process-and-domain baseline explains the encoded DNS transfer pattern",
                severity="info", subject_refs=[root_ref, archive_ref, endpoint_ref], evidence_refs=refs,
                analyzer="DnsExfiltrationCorrelationAnalyzer", confidence=0.9,
            ))
        else:
            findings.append(Finding(
                finding_id=f"finding-dns-exfil-{len(findings)+1:03d}", finding_type="confirmed_data_exfiltration",
                statement="Sensitive data staging was followed by a process-attributed encoded DNS transfer to an unapproved domain",
                severity="critical", subject_refs=[root_ref, archive_ref, endpoint_ref], evidence_refs=refs,
                analyzer="DnsExfiltrationCorrelationAnalyzer", confidence=0.95,
            ))
        relations.append(Relation(
            relation_id=f"rel-dns-exfil-{len(relations)+1:03d}", relation_type="exfiltrated_via",
            source_entity_ref=archive_ref, target_entity_ref=endpoint_ref,
            evidence_refs=[e.evidence_id for e in rows], confidence="confirmed", observed_at=rows[0].observed_at,
        ))
    return FactFindingBundle(findings=findings, relations=relations, limitations=[] if findings else ["No sensitive staging and encoded DNS transfer chain was established"])


def analyze_bulk_file_impact(state: InvestigationState, evidence_refs=None, parameters=None) -> FactFindingBundle:
    facts, findings, relations = [], [], []
    for event in [e for e in _ev(state, "file", evidence_refs) if e.evidence_type == "bulk_file_metric"]:
        count, rate, directories = int(event.data.get("modified_files", 0)), float(event.data.get("files_per_minute", 0)), int(event.data.get("directory_count", 0))
        root = event.data.get("root_process_ref") or event.data.get("process_ref")
        if not root or count <= 0:
            continue
        fact = Fact(fact_id=f"fact-bulk-impact-{len(facts)+1:03d}", fact_type="bulk_file_modification_observed", statement=f"{root} modified {count} files across {directories} directories at {rate:.1f} files/minute", subject_refs=[root], evidence_refs=[event.evidence_id], observed_at=event.observed_at, verification_method="BulkFileImpactAnalyzer/1.0")
        facts.append(fact)
        if count >= 100 and rate >= 20 and directories >= 3:
            findings.append(Finding(finding_id=f"finding-bulk-impact-{len(findings)+1:03d}", finding_type="broad_high_rate_file_impact", statement=f"High-rate changes affected {count} files in {directories} directories", severity="critical", subject_refs=[root], evidence_refs=[event.evidence_id], supporting_fact_refs=[fact.fact_id], analyzer="BulkFileImpactAnalyzer", confidence=0.96, limitations=["Bulk modification alone can be caused by authorized deployment or maintenance jobs"]))
        for target in event.data.get("affected_directory_refs") or []:
            relations.append(Relation(relation_id=f"rel-bulk-impact-{len(relations)+1:03d}", relation_type="modified_bulk", source_entity_ref=root, target_entity_ref=str(target), evidence_refs=[event.evidence_id], confidence="confirmed", observed_at=event.observed_at))
    return FactFindingBundle(facts=facts, findings=findings, relations=relations, limitations=[] if facts else ["No process-attributed file-impact metrics were available"])


def analyze_probable_file_encryption(state: InvestigationState, evidence_refs=None, parameters=None) -> FactFindingBundle:
    content = [e for e in _ev(state, "file", evidence_refs) if e.evidence_type == "file_content_change"]
    renames = [e for e in _ev(state, "file", evidence_refs) if e.evidence_type == "file_rename_pattern"]
    facts, findings = [], []
    roots = {e.data.get("root_process_ref") or e.data.get("process_ref") for e in [*content, *renames]} - {None}
    for root in roots:
        crows = [e for e in content if (e.data.get("root_process_ref") or e.data.get("process_ref")) == root]
        rrows = [e for e in renames if (e.data.get("root_process_ref") or e.data.get("process_ref")) == root]
        samples = sum(int(e.data.get("sample_count", 0)) for e in crows)
        entropy = max([float(e.data.get("mean_entropy_delta", 0)) for e in crows] or [0])
        header_ratio = max([float(e.data.get("header_changed_ratio", 0)) for e in crows] or [0])
        renamed = sum(int(e.data.get("renamed_files", 0)) for e in rrows)
        extension = next((str(e.data.get("new_extension")) for e in rrows if e.data.get("new_extension")), "")
        refs = [e.evidence_id for e in [*crows, *rrows]]
        if not refs:
            continue
        fact = Fact(fact_id=f"fact-content-change-{len(facts)+1:03d}", fact_type="file_content_transformation_observed", statement=f"{root} changed {samples} sampled file contents; entropy delta={entropy:.2f}, header-change ratio={header_ratio:.2f}, renamed={renamed}", subject_refs=[root], evidence_refs=refs, observed_at=next((e.observed_at for e in crows if e.observed_at), None), verification_method="ProbableFileEncryptionAnalyzer/1.0")
        facts.append(fact)
        if samples >= 20 and entropy >= 1.5 and header_ratio >= 0.8 and renamed >= 50 and extension:
            findings.append(Finding(finding_id=f"finding-file-encryption-{len(findings)+1:03d}", finding_type="probable_file_encryption", statement=f"Content transformation and {renamed} consistent renames to {extension} meet the deterministic probable-encryption threshold", severity="critical", subject_refs=[root], evidence_refs=refs, supporting_fact_refs=[fact.fact_id], analyzer="ProbableFileEncryptionAnalyzer", confidence=0.97, limitations=["This proves encryption-like transformation from telemetry, not the cryptographic algorithm or key custody"]))
    return FactFindingBundle(facts=facts, findings=findings, limitations=[] if facts else ["No content or rename telemetry was available"])


def analyze_recovery_inhibition(state: InvestigationState, evidence_refs=None, parameters=None) -> FactFindingBundle:
    rows = [e for e in _ev(state, "persistence", evidence_refs) if e.evidence_type in {"backup_destruction", "snapshot_activity"}] + [e for e in _ev(state, "process", evidence_refs) if e.evidence_type == "destructive_command"]
    successful = [e for e in rows if e.data.get("success") and e.data.get("outcome") in {"deleted", "disabled", "destroyed", "stopped"}]
    if not successful:
        return FactFindingBundle(limitations=["Destructive commands were absent or did not have a successful destructive outcome"])
    root = successful[0].data.get("root_process_ref") or successful[0].data.get("process_ref")
    refs = [e.evidence_id for e in successful]
    fact = Fact(fact_id="fact-recovery-inhibition-001", fact_type="recovery_capability_destroyed", statement=f"{len(successful)} backup or snapshot recovery actions completed successfully", subject_refs=[root] if root else [], evidence_refs=refs, observed_at=successful[0].observed_at, verification_method="RecoveryInhibitionAnalyzer/1.0")
    finding = Finding(finding_id="finding-recovery-inhibition-001", finding_type="recovery_inhibition", statement="The process tree successfully destroyed or disabled recovery capability", severity="critical", subject_refs=[root] if root else [], evidence_refs=refs, supporting_fact_refs=[fact.fact_id], analyzer="RecoveryInhibitionAnalyzer", confidence=0.98)
    return FactFindingBundle(facts=[fact], findings=[finding])


def analyze_ransom_note(state: InvestigationState, evidence_refs=None, parameters=None) -> FactFindingBundle:
    rows = [e for e in _ev(state, "file", evidence_refs) if e.evidence_type == "ransom_note" and e.data.get("success")]
    count = sum(int(e.data.get("created_count", 1)) for e in rows)
    if count < 2:
        return FactFindingBundle(limitations=["No repeated successful ransom-note creation was established"])
    root = rows[0].data.get("root_process_ref") or rows[0].data.get("process_ref")
    fact = Fact(fact_id="fact-ransom-note-001", fact_type="ransom_notes_created", statement=f"The process tree created {count} ransom-note files", subject_refs=[root] if root else [], evidence_refs=[e.evidence_id for e in rows], observed_at=rows[0].observed_at, verification_method="RansomNoteAnalyzer/1.0")
    finding = Finding(finding_id="finding-ransom-note-001", finding_type="ransom_demand_marker", statement="Repeated files containing a ransom demand were created in affected locations", severity="critical", subject_refs=[root] if root else [], evidence_refs=[e.evidence_id for e in rows], supporting_fact_refs=[fact.fact_id], analyzer="RansomNoteAnalyzer", confidence=0.98)
    return FactFindingBundle(facts=[fact], findings=[finding])


def analyze_service_disruption(state: InvestigationState, evidence_refs=None, parameters=None) -> FactFindingBundle:
    rows = [e for e in _ev(state, "persistence", evidence_refs) if e.evidence_type == "service_disruption" and e.data.get("success") and e.data.get("resulting_state") in {"inactive", "failed", "disabled"}]
    if not rows:
        return FactFindingBundle(limitations=["No successful service disruption was established"])
    root = rows[0].data.get("root_process_ref") or rows[0].data.get("process_ref")
    refs = [e.evidence_id for e in rows]
    fact = Fact(fact_id="fact-service-disruption-001", fact_type="services_disrupted", statement=f"{len(rows)} service disruption actions reached an inactive, failed or disabled state", subject_refs=[root] if root else [], evidence_refs=refs, observed_at=rows[0].observed_at, verification_method="ServiceDisruptionAnalyzer/1.0")
    finding = Finding(finding_id="finding-service-disruption-001", finding_type="actual_service_disruption", statement="The investigated process tree caused actual service disruption", severity="high", subject_refs=[root] if root else [], evidence_refs=refs, supporting_fact_refs=[fact.fact_id], analyzer="ServiceDisruptionAnalyzer", confidence=0.95)
    return FactFindingBundle(facts=[fact], findings=[finding])


def analyze_ransomware_chain(state: InvestigationState, evidence_refs=None, parameters=None) -> FactFindingBundle:
    rows = [e for e in state.evidence if not evidence_refs or e.evidence_id in set(evidence_refs)]
    types = {e.evidence_type for e in rows}
    roots = {e.data.get("root_process_ref") or e.data.get("process_ref") for e in rows} - {None}
    findings = []
    for root in roots:
        own = [e for e in rows if (e.data.get("root_process_ref") or e.data.get("process_ref")) in {None, root}]
        baseline = next((e for e in own if e.evidence_type == "authorized_batch_baseline" and e.data.get("approved") and (not e.data.get("root_process_ref") or e.data.get("root_process_ref") == root)), None)
        bulk = next((e for e in own if e.evidence_type == "bulk_file_metric" and int(e.data.get("modified_files", 0)) >= 100 and float(e.data.get("files_per_minute", 0)) >= 20 and int(e.data.get("directory_count", 0)) >= 3), None)
        content = next((e for e in own if e.evidence_type == "file_content_change" and int(e.data.get("sample_count", 0)) >= 20 and float(e.data.get("mean_entropy_delta", 0)) >= 1.5 and float(e.data.get("header_changed_ratio", 0)) >= 0.8), None)
        rename = next((e for e in own if e.evidence_type == "file_rename_pattern" and int(e.data.get("renamed_files", 0)) >= 50 and e.data.get("new_extension")), None)
        impact = [e for e in own if (e.evidence_type in {"backup_destruction", "snapshot_activity"} and e.data.get("success") and e.data.get("outcome") in {"deleted", "disabled", "destroyed"}) or (e.evidence_type == "ransom_note" and e.data.get("success") and int(e.data.get("created_count", 1)) >= 2)]
        refs = [e.evidence_id for e in own]
        if baseline and bulk and (content or rename):
            findings.append(Finding(finding_id="finding-legitimate-batch-001", finding_type="legitimate_batch_explanation", statement="An approved process, change window and file scope explain the broad batch transformation", severity="info", subject_refs=[root], evidence_refs=refs, analyzer="RansomwareChainAnalyzer", confidence=0.96))
        elif bulk and content and rename and impact:
            findings.append(Finding(finding_id="finding-ransomware-chain-001", finding_type="confirmed_ransomware_impact", statement="The same process tree caused broad high-rate modifications, encryption-like content changes, consistent renames and destructive impact", severity="critical", subject_refs=[root], evidence_refs=refs, analyzer="RansomwareChainAnalyzer", confidence=0.99))
    return FactFindingBundle(findings=findings, limitations=[] if findings else [f"No complete ransomware chain was established from evidence types {sorted(types)}"])


def analyze_cross_host_path(state: InvestigationState, evidence_refs=None, parameters=None) -> FactFindingBundle:
    selected = set(evidence_refs or [])
    rows = [e for e in state.evidence if not selected or e.evidence_id in selected]
    transfers = [e for e in rows if e.evidence_type == "file_transfer_cross_host" and e.data.get("success")]
    presences = [e for e in rows if e.evidence_type == "hash_presence" and e.data.get("present")]
    logins = [e for e in rows if e.evidence_type == "remote_login_session" and e.data.get("success")]
    contexts = [e for e in rows if e.evidence_type == "host_asset_context"]
    facts, findings, relations = [], [], []
    for transfer in transfers:
        source, target = transfer.data.get("source_host_id"), transfer.data.get("target_host_id")
        if not source or not target:
            continue
        transfer_hash = transfer.data.get("file_hash")
        presence = next((e for e in presences if e.data.get("host_id") == target and (not transfer_hash or e.data.get("file_hash") == transfer_hash)), None)
        login = next((e for e in logins if e.data.get("source_host_id") == source and e.data.get("target_host_id") == target), None)
        context = next((e for e in contexts if e.data.get("host_id") == target), None)
        refs = [transfer.evidence_id, *([presence.evidence_id] if presence else []), *([login.evidence_id] if login else []), *([context.evidence_id] if context else [])]
        fact = Fact(fact_id=f"fact-cross-host-transfer-{len(facts)+1:03d}", fact_type="cross_host_file_transfer_observed", statement=f"A file transfer from {source} to {target} completed successfully", subject_refs=[f"host:{source}", f"host:{target}"], evidence_refs=[transfer.evidence_id], observed_at=transfer.observed_at, verification_method="CrossHostPathAnalyzer/1.0")
        facts.append(fact)
        relations.append(Relation(relation_id=f"rel-cross-host-{len(relations)+1:03d}", relation_type="transferred_file_to", source_entity_ref=f"host:{source}", target_entity_ref=f"host:{target}", evidence_refs=[transfer.evidence_id], confidence="confirmed", observed_at=transfer.observed_at))
        approved = bool(context and context.data.get("approved_deployment") and context.data.get("deployment_id") == transfer.data.get("deployment_id"))
        if approved and presence:
            findings.append(Finding(finding_id="finding-approved-deployment-001", finding_type="legitimate_multi_host_deployment", statement="Approved deployment context explains the same file on the target host", severity="info", subject_refs=[f"host:{source}", f"host:{target}"], evidence_refs=refs, supporting_fact_refs=[fact.fact_id], analyzer="CrossHostPathAnalyzer", confidence=0.97))
        elif presence and login and presence.data.get("executed"):
            findings.append(Finding(finding_id="finding-lateral-propagation-001", finding_type="confirmed_lateral_file_propagation", statement="The source host authenticated to the target, transferred the investigated hash, and that hash executed on the target", severity="critical", subject_refs=[f"host:{source}", f"host:{target}"], evidence_refs=refs, supporting_fact_refs=[fact.fact_id], analyzer="CrossHostPathAnalyzer", confidence=0.98))
        else:
            findings.append(Finding(finding_id=f"finding-cross-host-lead-{len(findings)+1:03d}", finding_type="cross_host_transfer_lead", statement="A direct file-transfer lead exists, but target presence and execution are not both proven", severity="medium", subject_refs=[f"host:{source}", f"host:{target}"], evidence_refs=refs, supporting_fact_refs=[fact.fact_id], analyzer="CrossHostPathAnalyzer", confidence=0.7, limitations=["Do not infer lateral execution from a shared endpoint or transfer record alone"]))
    if not transfers and any(e.evidence_type in {"internal_connection", "shared_endpoint_host"} for e in rows):
        refs = [e.evidence_id for e in rows if e.evidence_type in {"internal_connection", "shared_endpoint_host"}]
        findings.append(Finding(finding_id="finding-shared-infrastructure-001", finding_type="shared_infrastructure_only", statement="Hosts share a connection or external endpoint, but no direct file transfer was established", severity="info", evidence_refs=refs, analyzer="CrossHostPathAnalyzer", confidence=0.95, limitations=["Shared C2 infrastructure is not direct propagation evidence"]))
    return FactFindingBundle(facts=facts, findings=findings, relations=relations, limitations=[] if findings else ["No cross-host path could be established"])


def analyze_cross_host_lead(state: InvestigationState, evidence_refs=None, parameters=None) -> FactFindingBundle:
    selected = set(evidence_refs or [])
    rows = [e for e in state.evidence if (not selected or e.evidence_id in selected) and e.evidence_type in {"file_transfer_cross_host", "internal_connection", "shared_endpoint_host"}]
    transfers = [e for e in rows if e.evidence_type == "file_transfer_cross_host" and e.data.get("success")]
    if transfers:
        event = transfers[0]
        source, target = event.data.get("source_host_id"), event.data.get("target_host_id")
        fact = Fact(fact_id="fact-cross-host-lead-001", fact_type="cross_host_candidate_observed", statement=f"Direct file-transfer evidence identifies candidate host {target}", subject_refs=[f"host:{source}", f"host:{target}"], evidence_refs=[event.evidence_id], observed_at=event.observed_at, verification_method="CrossHostLeadAnalyzer/1.0")
        finding = Finding(finding_id="finding-cross-host-lead-001", finding_type="cross_host_transfer_lead", statement="A successful file transfer directly identifies a candidate host for controlled scope expansion", severity="medium", subject_refs=[f"host:{source}", f"host:{target}"], evidence_refs=[event.evidence_id], supporting_fact_refs=[fact.fact_id], analyzer="CrossHostLeadAnalyzer", confidence=0.9)
        return FactFindingBundle(facts=[fact], findings=[finding])
    if rows:
        finding = Finding(finding_id="finding-shared-infrastructure-001", finding_type="shared_infrastructure_only", statement="A related host shares an internal connection or external endpoint, but no direct file transfer is proven", severity="info", evidence_refs=[e.evidence_id for e in rows], analyzer="CrossHostLeadAnalyzer", confidence=0.95, limitations=["This evidence is insufficient to authorize a propagation conclusion"])
        return FactFindingBundle(findings=[finding])
    return FactFindingBundle(limitations=["No cross-host lead was observed"])


ANALYZERS = {
    "analyze_execution": verify_execution,
    "analyze_process_chain": analyze_process_chain,
    "analyze_network": analyze_network,
    "analyze_remote_command": analyze_remote_command,
    "analyze_persistence": analyze_persistence,
    "analyze_reputation": analyze_reputation,
    "analyze_file_provenance": analyze_file_provenance,
    "analyze_sensitive_discovery": analyze_sensitive_discovery,
    "analyze_credential_access": analyze_credential_access,
    "analyze_data_staging": analyze_data_staging,
    "analyze_data_transfer": analyze_data_transfer,
    "analyze_dns_tunneling": analyze_dns_tunneling,
    "analyze_https_exfiltration": analyze_https_exfiltration,
    "analyze_dns_exfiltration": analyze_dns_exfiltration,
    "analyze_bulk_file_impact": analyze_bulk_file_impact,
    "analyze_probable_file_encryption": analyze_probable_file_encryption,
    "analyze_recovery_inhibition": analyze_recovery_inhibition,
    "analyze_ransom_note": analyze_ransom_note,
    "analyze_service_disruption": analyze_service_disruption,
    "analyze_ransomware_chain": analyze_ransomware_chain,
    "analyze_cross_host_path": analyze_cross_host_path,
    "analyze_cross_host_lead": analyze_cross_host_lead,
}
