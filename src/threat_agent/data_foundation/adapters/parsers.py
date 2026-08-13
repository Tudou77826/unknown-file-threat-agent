from __future__ import annotations

from datetime import datetime
from typing import Any

from ...contracts import (
    AssetActivity,
    ExtensionActivity,
    FileActivity,
    NetworkActivity,
    NormalizedActivity,
    PackageActivity,
    ProcessActivity,
    RawRecordEnvelope,
    ServiceActivity,
    SocketActivity,
)


def _common(record: RawRecordEnvelope, activity_id: str, subject_refs: list[str]) -> dict[str, Any]:
    return {
        "tenant_id": record.tenant_id,
        "source_identity": f"parser:{record.parser_version}",
        "activity_id": activity_id,
        "observed_at": record.observed_at,
        "ingested_at": record.ingested_at,
        "source_system": record.source_system,
        "source_record_id": record.source_record_id,
        "subject_refs": subject_refs,
        "raw_record_ref": record.raw_record_id,
        "normalizer_version": record.parser_version,
    }


def _pid(process_ref: str | None) -> int:
    if process_ref:
        parts = process_ref.split(":")
        if len(parts) >= 3 and parts[-2].isdigit():
            return int(parts[-2])
    return 0


def _started(process_ref: str | None) -> datetime | None:
    if process_ref:
        value = process_ref.split(":")[-1]
        if value.isdigit() and len(value) >= 10:
            return datetime.fromtimestamp(int(value) / 1000, tz=record_timezone())
    return None


def record_timezone():
    from datetime import timezone

    return timezone.utc


class ReferenceEventParser:
    name = "reference-event"
    version = "1.0"

    def parse(
        self, record: RawRecordEnvelope, payload: dict[str, Any]
    ) -> list[NormalizedActivity]:
        event_type = str(payload["event_type"])
        host = str(payload.get("host_id") or "")
        subjects = [str(item) for item in payload.get("subject_refs") or []]
        data = dict(payload.get("data") or {})
        if host:
            data.setdefault("host_id", host)
        base = _common(record, f"activity-{record.source_record_id}", subjects or [f"host:{host}"])
        base["extension"] = {
            "source_event_type": event_type,
            "source_domain": str(payload.get("domain") or "unknown"),
            "source_data": data,
            "source_subject_refs": subjects,
        }
        result: list[NormalizedActivity] = []

        if event_type in {"process_exec", "child_process_exec"}:
            process_ref = str(data.get("process_ref") or next((x for x in subjects if x.startswith("process:")), ""))
            result.append(ProcessActivity(
                **base, host_ref=host, process_ref=process_ref, pid=_pid(process_ref),
                process_started_at=_started(process_ref), executable=data.get("executable"),
                command_line=data.get("cmdline"), operation="execute",
                target_refs=[str(data["file_ref"])] if data.get("file_ref") else [],
            ))
            if data.get("file_ref"):
                result.append(FileActivity(
                    **{**base, "activity_id": f"activity-{record.source_record_id}-file"},
                    host_ref=host, file_ref=str(data["file_ref"]), path=data.get("executable"),
                    acting_process_ref=process_ref, operation="execute",
                ))
        elif event_type == "process_parent_relation":
            child = str(data.get("child_ref") or "")
            result.append(ProcessActivity(
                **base, host_ref=host, process_ref=child, pid=_pid(child),
                process_started_at=_started(child), parent_process_ref=data.get("parent_ref"),
                operation="create",
            ))
        elif event_type == "network_connection":
            endpoint = next((x for x in subjects if x.startswith("endpoint:")), None)
            result.append(NetworkActivity(
                **base, host_ref=host, process_ref=data.get("process_ref"),
                destination_endpoint_ref=endpoint, protocol=data.get("protocol"),
                direction="outbound", operation="connect", outcome="success",
            ))
        elif event_type == "socket_io":
            direction = "receive" if data.get("direction") == "inbound" else "send"
            result.append(SocketActivity(
                **base, host_ref=host, process_ref=data.get("process_ref"),
                socket_ref=str(data["socket_id"]), direction=direction,
                byte_count=data.get("bytes"),
            ))
        elif event_type == "systemd_event":
            operation_map = {"unit_write": "define", "enable": "enable", "start": "start", "stop": "stop"}
            result.append(ServiceActivity(
                **base, host_ref=host, service_ref=str(data.get("unit") or "unknown-service"),
                executable_ref=data.get("exec_file_ref"),
                operation=operation_map.get(str(data.get("action")), "define"),
            ))
            if data.get("exec_file_ref"):
                result.append(FileActivity(
                    **{**base, "activity_id": f"activity-{record.source_record_id}-file"},
                    host_ref=host, file_ref=str(data["exec_file_ref"]), path=data.get("unit_path"),
                    operation="observe",
                ))
        elif event_type == "package_provenance":
            package = str(data.get("package") or f"package-observation:{record.source_record_id}")
            file_ref = next((x for x in subjects if x.startswith("file:")), None)
            result.append(PackageActivity(
                **base, host_ref=host, package_ref=package, file_ref=file_ref,
                repository=data.get("repository"), signature_valid=data.get("signature_valid"),
                operation="ownership_observed",
            ))
        elif event_type == "approved_endpoint":
            result.append(AssetActivity(
                **base, asset_ref=host, operation="approve" if data.get("approved") else "observe",
                attributes=data,
            ))
        else:
            result.append(ExtensionActivity(
                **base, extension_schema=f"reference/{payload.get('domain', 'unknown')}/{event_type}/1.0",
            ))
        return result


class VendorEnvelopeParser:
    """Parser for a deliberately different nested vendor event format."""

    name = "vendor-envelope"
    version = "1.0"

    def parse(
        self, record: RawRecordEnvelope, payload: dict[str, Any]
    ) -> list[NormalizedActivity]:
        category = str(payload["category"])
        event = dict(payload.get("event") or {})
        host = str(payload["device"]["id"])
        entity = dict(payload.get("entity") or {})
        base = _common(record, f"activity-{record.source_record_id}", [str(entity["id"])])
        base["extension"] = {
            "source_event_type": str(event.get("type") or category),
            "source_domain": category,
            "source_data": event,
            "source_subject_refs": [str(entity["id"])],
        }
        if category == "process":
            process_ref = str(entity["id"])
            return [ProcessActivity(
                **base, host_ref=host, process_ref=process_ref, pid=int(event["pid"]),
                process_started_at=event.get("started_at"), executable=event.get("image"),
                command_line=event.get("command_line"), parent_process_ref=event.get("parent_ref"),
                operation=str(event.get("operation", "execute")),
            )]
        if category == "network":
            return [NetworkActivity(
                **base, host_ref=host, process_ref=event.get("process_ref"),
                destination_endpoint_ref=event.get("destination_ref"), protocol=event.get("protocol"),
                direction=str(event.get("direction", "outbound")),
                operation=str(event.get("operation", "connect")), outcome=str(event.get("outcome", "unknown")),
            )]
        if category == "file":
            return [FileActivity(
                **base, host_ref=host, file_ref=str(entity["id"]), path=event.get("path"),
                content_digest=event.get("digest"), acting_process_ref=event.get("process_ref"),
                operation=str(event.get("operation", "observe")),
            )]
        raise ValueError(f"unsupported vendor category: {category}")
