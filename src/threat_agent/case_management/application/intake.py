from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from ...contracts import Entity, InvestigationToolLedger, Scope
from ...judgment.domain.models import Claim, InvestigationState


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


def _single_alert_host(raw: dict[str, Any]) -> str:
    """Return the one alert host for this run, rejecting missing or multi-host input.

    ``Sub_asset`` is the alert host; ``source`` names the reporting system and
    is only a fallback when the asset field is absent.
    """
    candidate = pick(raw, "sub_asset")
    if candidate in (None, ""):
        candidate = pick(raw, "source")
    if isinstance(candidate, (list, tuple, set)):
        unique = sorted({str(item) for item in candidate if item not in (None, "")})
        if len(unique) != 1:
            raise ValueError(
                f"Input must provide a single alert host; got {unique or 'no host'}"
            )
        candidate = unique[0]
    host_id = str(candidate or "")
    if not host_id:
        raise ValueError("Input must provide File_hash/fileHash, File_path/filePath and source/Sub_asset")
    return host_id


def initialize_state(raw: dict[str, Any], *, lookback_hours: float = 24.0) -> InvestigationState:
    sha256 = str(pick(raw, "sha256", "")).lower()
    path = str(pick(raw, "path", ""))
    if not sha256 or not path:
        raise ValueError("Input must provide File_hash/fileHash, File_path/filePath and source/Sub_asset")
    host_id = _single_alert_host(raw)
    detail, detail_limits = parse_detail(pick(raw, "detail"))
    case_seed = str(pick(raw, "file_id") or f"{host_id}:{sha256}")
    case_id = "case-" + hashlib.sha256(case_seed.encode()).hexdigest()[:12]
    file_id = f"file:{host_id}:{sha256}"
    host_entity = Entity(entity_id=f"host:{host_id}", entity_type="host", attributes={"source": pick(raw, "source"), "sub_asset": pick(raw, "sub_asset")})
    file_entity = Entity(entity_id=file_id, entity_type="file", attributes={"sha256": sha256, "path": path, "file_type": pick(raw, "file_type"), "size": pick(raw, "size"), "mode": pick(raw, "mode"), "status": pick(raw, "status")})
    entities = [host_entity, file_entity]

    claims: list[Claim] = []
    for cidx, context in enumerate(detail.get("context", []) or []):
        target_pid = str(context.get("pid", ""))
        target_start = millis(context.get("processStartTime") or context.get("processStarTime"))
        proc_id = f"process:{host_id}:{target_pid}:{int(target_start.timestamp()*1000) if target_start else 'unknown'}"
        chain = [{"raw_index": tidx, **parent} for tidx, parent in enumerate(context.get("tree", []) or [])]
        entities.append(Entity(entity_id=proc_id, entity_type="process", attributes={
            "pid": target_pid,
            "path": context.get("path"),
            "euid": context.get("euid"),
            "cmdline": context.get("cmdline"),
            "start_time": target_start.isoformat() if target_start else None,
            "context_index": cidx,
            "tree_direct_parent_to_root": chain,
        }))
        claims.append(Claim(claim_id=f"claim-process-chain-{cidx+1:03d}", claim_type="reported_process_chain", statement=f"Upstream reports a process chain for PID {target_pid}", source_evidence_refs=[], verification_requirements=["query process execution events", "verify PID and start time", "verify parent-child relations"]))

    discovery = millis(pick(raw, "discovery_time"))
    # The maximum lookback is a deployment decision (INVESTIGATION_LOOKBACK_HOURS):
    # persistence and low-frequency C2 often precede the alert by more than the
    # old fixed 15 minutes.
    start = discovery - timedelta(hours=lookback_hours) if discovery else None
    end = millis(pick(raw, "recent_time")) or discovery
    return InvestigationState(
        case_id=case_id,
        raw_input=raw,
        entities=entities,
        claims=claims,
        scope=Scope(host_ids=[host_id], container_ids=[str(x) for x in [pick(raw, "container_id")] if x], entity_ids=[file_id], start_time=start, end_time=end),
        tool_ledger=InvestigationToolLedger(
            # Intake anchors: every entity minted here lives on the alert host
            # and may seed authorized entity exploration.
            authorized_entity_refs=[entity.entity_id for entity in entities],
        ),
    )
