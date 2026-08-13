from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from ..shared import StrictModel
from .common import TenantContractModel


class RawRecordEnvelope(TenantContractModel):
    raw_record_id: str = Field(min_length=1)
    source_system: str = Field(min_length=1)
    source_record_id: str = Field(min_length=1)
    observed_at: datetime
    ingested_at: datetime
    connector_version: str = Field(min_length=1)
    parser_version: str = Field(min_length=1)
    payload_ref: str = Field(min_length=1)
    payload_digest: str = Field(min_length=1)
    access_labels: list[str] = Field(default_factory=list)


class ActivityEnvelope(TenantContractModel):
    activity_id: str = Field(min_length=1)
    activity_type: str = Field(min_length=1)
    observed_at: datetime
    ingested_at: datetime
    source_system: str = Field(min_length=1)
    source_record_id: str = Field(min_length=1)
    subject_refs: list[str] = Field(min_length=1)
    actor_refs: list[str] = Field(default_factory=list)
    target_refs: list[str] = Field(default_factory=list)
    outcome: Literal["success", "failure", "unknown"] = "unknown"
    raw_record_ref: str = Field(min_length=1)
    normalizer_version: str = Field(min_length=1)
    extension: dict[str, Any] = Field(default_factory=dict)


class ProcessActivity(ActivityEnvelope):
    activity_type: Literal["process"] = "process"
    host_ref: str = Field(min_length=1)
    process_ref: str = Field(min_length=1)
    pid: int = Field(ge=0)
    process_started_at: datetime | None = None
    executable: str | None = None
    command_line: str | None = None
    parent_process_ref: str | None = None
    operation: Literal["create", "execute", "terminate"]


class NetworkActivity(ActivityEnvelope):
    activity_type: Literal["network"] = "network"
    host_ref: str = Field(min_length=1)
    process_ref: str | None = None
    source_endpoint_ref: str | None = None
    destination_endpoint_ref: str | None = None
    protocol: str | None = None
    direction: Literal["inbound", "outbound", "unknown"] = "unknown"
    operation: Literal["connect", "accept", "listen", "close"]


class SocketActivity(ActivityEnvelope):
    activity_type: Literal["socket"] = "socket"
    host_ref: str = Field(min_length=1)
    process_ref: str | None = None
    socket_ref: str = Field(min_length=1)
    direction: Literal["send", "receive"]
    byte_count: int | None = Field(default=None, ge=0)


class FileActivity(ActivityEnvelope):
    activity_type: Literal["file"] = "file"
    host_ref: str = Field(min_length=1)
    file_ref: str = Field(min_length=1)
    path: str | None = None
    content_digest: str | None = None
    acting_process_ref: str | None = None
    operation: Literal["create", "write", "rename", "delete", "execute", "observe"]


class ServiceActivity(ActivityEnvelope):
    activity_type: Literal["service"] = "service"
    host_ref: str = Field(min_length=1)
    service_ref: str = Field(min_length=1)
    executable_ref: str | None = None
    operation: Literal["define", "enable", "disable", "start", "stop"]


class PackageActivity(ActivityEnvelope):
    activity_type: Literal["package"] = "package"
    host_ref: str = Field(min_length=1)
    package_ref: str = Field(min_length=1)
    file_ref: str | None = None
    repository: str | None = None
    signature_valid: bool | None = None
    operation: Literal["install", "remove", "upgrade", "ownership_observed", "signature_observed"]


class AssetActivity(ActivityEnvelope):
    activity_type: Literal["asset"] = "asset"
    asset_ref: str = Field(min_length=1)
    operation: Literal["observe", "update", "approve", "revoke"]
    attributes: dict[str, Any] = Field(default_factory=dict)
    valid_from: datetime | None = None
    valid_to: datetime | None = None


class ExtensionActivity(ActivityEnvelope):
    activity_type: Literal["extension"] = "extension"
    extension_schema: str = Field(min_length=1)

    @model_validator(mode="after")
    def require_extension_payload(self) -> "ExtensionActivity":
        if not self.extension:
            raise ValueError("extension activity requires a non-empty extension payload")
        return self


NormalizedActivity = Annotated[
    ProcessActivity
    | NetworkActivity
    | SocketActivity
    | FileActivity
    | ServiceActivity
    | PackageActivity
    | AssetActivity
    | ExtensionActivity,
    Field(discriminator="activity_type"),
]


class EntityAlias(StrictModel):
    source_system: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    valid_from: datetime | None = None
    valid_to: datetime | None = None


class EntityIdentity(TenantContractModel):
    entity_id: str = Field(min_length=1)
    entity_type: Literal[
        "host", "file", "process", "user", "network_endpoint", "package", "service",
        "business_asset",
    ]
    aliases: list[EntityAlias] = Field(default_factory=list)
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    resolution_confidence: float = Field(default=1.0, ge=0, le=1)
    attributes: dict[str, Any] = Field(default_factory=dict)


class ObservedRelation(TenantContractModel):
    relation_id: str = Field(min_length=1)
    relation_type: str = Field(min_length=1)
    source_entity_ref: str = Field(min_length=1)
    target_entity_ref: str = Field(min_length=1)
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    supporting_activity_refs: list[str] = Field(default_factory=list)
    resolution_status: Literal["resolved", "candidate"]
    confidence: float = Field(ge=0, le=1)
    ambiguity_reason: str | None = None
    resolver_version: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_resolution(self) -> "ObservedRelation":
        if self.resolution_status == "resolved" and not self.supporting_activity_refs:
            raise ValueError("resolved relation requires supporting_activity_refs")
        if self.resolution_status == "candidate" and not self.ambiguity_reason:
            raise ValueError("candidate relation requires ambiguity_reason")
        return self
