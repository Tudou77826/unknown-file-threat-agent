from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from .models import Claim, Entity, Evidence, EvidenceGap, EvidenceRole, EvidenceStatus, Hypothesis, InvestigationState, Scope


ALIASES = {
    "file_id": ("File_id", "file_id"),
    "sha256": ("File_hash", "fileHash", "file_hash"),
    "path": ("File_path", "filePath", "file_path"),
    "file_type": ("File_type", "fileType", "file_type"),
    "size": ("File_size", "fileSize", "file_size"),
    "mode": ("File_mode", "fileMode", "file_mode"),
    "source": ("source", "Source"),
    "sub_asset": ("Sub_asset", "Sub_Asset", "sub_asset"),
    "status": ("status", "Status"),
    "sync_status": ("Sync_status", "sync_status"),
    "discovery_time": ("discovery_time", "Discovery_Time"),
    "recent_time": ("Recent_time", "recent_time"),
    "process_create_time": ("Process_create_time", "PROCESS_CREATE_TIME"),
    "realtime_type": ("Realtime_type", "REALTIME_TYPE"),
    "detail": ("Detail", "DETAIL"),
    "pod_id": ("Pod_id", "POD_ID"),
    "container_id": ("Container_id", "CONTAINER_ID"),
    "container_name": ("Container_name", "CONTAINER_NAME"),
}


def pick(raw: dict[str, Any], name: str, default: Any = None) -> Any:
    for key in ALIASES.get(name, (name,)):
        if key in raw and raw[key] is not None:
            return raw[key]
    return default


def millis(value: Any) -> datetime | None:
    if value in (None, "", "null"):
        return None
    try:
        return datetime.fromtimestamp(float(value) / 1000.0, tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


def parse_detail(value: Any) -> tuple[dict[str, Any], list[str]]:
    if value in (None, ""):
        return {}, ["Detail is missing"]
    if isinstance(value, dict):
        return value, []
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return (parsed, []) if isinstance(parsed, dict) else ({}, ["Detail JSON root is not an object"])
        except json.JSONDecodeError as exc:
            return {}, [f"Detail is invalid JSON: {exc.msg}"]
    return {}, [f"Unsupported Detail type: {type(value).__name__}"]


def initialize_state(raw: dict[str, Any]) -> InvestigationState:
    sha256 = str(pick(raw, "sha256", "")).lower()
    path = str(pick(raw, "path", ""))
    host_id = str(pick(raw, "sub_asset") or pick(raw, "source") or "unknown-host")
    if not sha256 or not path or host_id == "unknown-host":
        raise ValueError("Input must provide File_hash/fileHash, File_path/filePath and source/Sub_asset")
    detail, detail_limits = parse_detail(pick(raw, "detail"))
    case_seed = str(pick(raw, "file_id") or f"{host_id}:{sha256}")
    case_id = "case-" + hashlib.sha256(case_seed.encode()).hexdigest()[:12]
    file_id = f"file:{host_id}:{sha256}"
    host_entity = Entity(entity_id=f"host:{host_id}", entity_type="host", attributes={"source": pick(raw, "source"), "sub_asset": pick(raw, "sub_asset")})
    file_entity = Entity(entity_id=file_id, entity_type="file", attributes={"sha256": sha256, "path": path, "file_type": pick(raw, "file_type"), "size": pick(raw, "size"), "mode": pick(raw, "mode"), "status": pick(raw, "status")})
    entities = [host_entity, file_entity]

    input_ev = Evidence(
        evidence_id="ev-input-file-001", evidence_type="upstream_file_observation", domain="file",
        source_system="unknown-file-detection", observed_at=millis(pick(raw, "discovery_time")),
        subject_refs=[host_entity.entity_id, file_id], data={"sha256": sha256, "path": path, "status": pick(raw, "status"), "sync_status": pick(raw, "sync_status")},
        limitations=detail_limits, raw_reference=f"raw-input://{pick(raw, 'file_id', case_id)}",
    )
    evidence = [input_ev]
    claims: list[Claim] = []

    for cidx, context in enumerate(detail.get("context", []) or []):
        target_pid = str(context.get("pid", ""))
        target_start = millis(context.get("processStartTime") or context.get("processStarTime"))
        proc_id = f"process:{host_id}:{target_pid}:{int(target_start.timestamp()*1000) if target_start else 'unknown'}"
        entities.append(Entity(entity_id=proc_id, entity_type="process", attributes={"pid": target_pid, "path": context.get("path"), "euid": context.get("euid"), "cmdline": context.get("cmdline"), "start_time": target_start.isoformat() if target_start else None, "context_index": cidx}))
        chain = []
        for tidx, parent in enumerate(context.get("tree", []) or []):
            chain.append({"raw_index": tidx, **parent})
        evidence.append(Evidence(evidence_id=f"ev-input-chain-{cidx+1:03d}", evidence_type="upstream_process_chain", domain="process", source_system="unknown-file-detection", observed_at=target_start, subject_refs=[file_id, proc_id], data={"target": context, "tree_direct_parent_to_root": chain, "upstream_primary_context": cidx == 0}, raw_reference=f"raw-input://{pick(raw, 'file_id', case_id)}/detail/context/{cidx}"))
        claims.append(Claim(claim_id=f"claim-process-chain-{cidx+1:03d}", claim_type="reported_process_chain", statement=f"Upstream reports a process chain for PID {target_pid}", source_evidence_refs=[f"ev-input-chain-{cidx+1:03d}"], verification_requirements=["query process execution events", "verify PID and start time", "verify parent-child relations"]))

    discovery = millis(pick(raw, "discovery_time"))
    start = discovery - timedelta(minutes=15) if discovery else None
    end = millis(pick(raw, "recent_time")) or discovery
    state = InvestigationState(
        case_id=case_id, raw_input=raw, entities=entities, claims=claims, evidence=evidence,
        hypotheses=[Hypothesis(hypothesis_id="hyp-c2-001", hypothesis_type="backdoor_c2", statement="The unknown file may participate in backdoor or C2 activity")],
        evidence_roles=[
            EvidenceRole(role_id="role-execution", role_type="execution", question="Was the file independently confirmed to execute?", hypothesis_refs=["hyp-c2-001"], required_evidence_types=["process_exec"], required_for_verdict=True),
            EvidenceRole(role_id="role-attribution", role_type="attribution", question="Can subsequent behavior be attributed to the file's process chain?", hypothesis_refs=["hyp-c2-001"], required_evidence_types=["process_parent_relation"], required_for_verdict=True),
            EvidenceRole(role_id="role-c2-behavior", role_type="behavior", question="Did the process communicate externally or execute remote commands?", hypothesis_refs=["hyp-c2-001"], required_evidence_types=["network_connection", "socket_io", "child_process_exec"], required_for_verdict=True),
            EvidenceRole(role_id="role-persistence", role_type="behavior", question="Did the file establish an active persistence mechanism?", hypothesis_refs=["hyp-c2-001"], required_evidence_types=["systemd_event"], required_for_verdict=True),
            EvidenceRole(role_id="role-counter-evidence", role_type="counter_evidence", question="Is there a legitimate provenance and operations explanation?", hypothesis_refs=["hyp-c2-001"], required_evidence_types=["package_provenance", "approved_endpoint"], required_for_verdict=True),
        ],
        evidence_gaps=[
            EvidenceGap(gap_id="gap-execution", gap_type="execution", question="Was the unknown file actually executed?", reason="Execution is required before runtime behavior can be attributed", required_evidence_types=["process_exec"], recommended_tools=["query_process_execution"], priority="critical"),
            EvidenceGap(gap_id="gap-process-chain", gap_type="process_chain", question="What independently verified process ancestry and children surround execution?", reason="Needed to attribute origin and subsequent commands", required_evidence_types=["process_parent_relation"], recommended_tools=["query_process_relations"], priority="critical"),
            EvidenceGap(gap_id="gap-network", gap_type="network_behavior", question="Did the process communicate with external endpoints?", reason="Needed to evaluate C2 behavior", required_evidence_types=["network_connection"], recommended_tools=["query_process_network"], priority="high"),
            EvidenceGap(gap_id="gap-remote-command", gap_type="remote_command", question="Did inbound network activity drive child command execution and outbound results?", reason="Needed to distinguish beaconing from interactive control", required_evidence_types=["socket_io", "child_process_exec"], recommended_tools=["query_socket_activity", "query_child_process_execution"], priority="critical"),
            EvidenceGap(gap_id="gap-persistence", gap_type="persistence", question="Did the file establish active Linux persistence?", reason="Needed to evaluate durable control", required_evidence_types=["systemd_event"], recommended_tools=["query_systemd_events"], priority="high"),
            EvidenceGap(gap_id="gap-counter", gap_type="counter_evidence", question="Is there a legitimate software and operations explanation?", reason="Required to control false positives", required_evidence_types=["package_provenance", "approved_endpoint"], recommended_tools=["query_package_provenance", "query_approved_endpoints"], priority="high"),
        ],
        scope=Scope(host_ids=[host_id], container_ids=[str(x) for x in [pick(raw, "container_id")] if x], entity_ids=[file_id], start_time=start, end_time=end),
    )
    expansion_policy = raw.get("Scope_expansion_policy") or raw.get("scope_expansion_policy")
    if expansion_policy:
        state.scope.expansion_policy = str(expansion_policy)
    requested_scenarios = raw.get("Investigation_scenarios") or raw.get("investigation_scenarios") or []
    if requested_scenarios and "c2" not in requested_scenarios:
        state.active_scenarios = []
        c2_only_gap_ids = {"gap-process-chain", "gap-network", "gap-remote-command", "gap-persistence", "gap-counter"}
        for gap in state.evidence_gaps:
            if gap.gap_id in c2_only_gap_ids:
                gap.status = "unresolvable"
                gap.resolution = "unresolvable"
                gap.limitations.append("The input selected an explicit non-C2 scenario profile; this C2 branch was not activated")
        for role in state.evidence_roles:
            if role.role_id != "role-execution":
                role.status = "unavailable"
    if requested_scenarios:
        from .scenarios import activate_scenario
        for scenario in requested_scenarios:
            if scenario != "c2":
                activate_scenario(state, str(scenario), [input_ev.evidence_id])
    return state
