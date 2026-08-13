from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .common import ContractModel
from .evidence import Scope


class ActivityQueryBase(ContractModel):
    run_id: str = Field(min_length=1)
    query_id: str = Field(min_length=1)
    activity_type: str = Field(min_length=1)
    scope: Scope
    host_refs: list[str] = Field(default_factory=list)
    entity_refs: list[str] = Field(default_factory=list)
    start_time: datetime | None = None
    end_time: datetime | None = None
    source_event_types: list[str] = Field(default_factory=list)
    limit: int = Field(default=200, ge=1, le=1000)
    cursor: str | None = None

    @model_validator(mode="after")
    def validate_time_range(self) -> "ActivityQueryBase":
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValueError("start_time cannot be after end_time")
        return self


class ProcessActivityQuery(ActivityQueryBase):
    activity_type: Literal["process"] = "process"
    process_refs: list[str] = Field(default_factory=list)
    operations: list[Literal["create", "execute", "terminate"]] = Field(default_factory=list)
    executable: str | None = None


class NetworkActivityQuery(ActivityQueryBase):
    activity_type: Literal["network"] = "network"
    process_refs: list[str] = Field(default_factory=list)
    endpoint_refs: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)


class SocketActivityQuery(ActivityQueryBase):
    activity_type: Literal["socket"] = "socket"
    process_refs: list[str] = Field(default_factory=list)
    socket_refs: list[str] = Field(default_factory=list)


class FileActivityQuery(ActivityQueryBase):
    activity_type: Literal["file"] = "file"
    file_refs: list[str] = Field(default_factory=list)
    process_refs: list[str] = Field(default_factory=list)
    operations: list[Literal["create", "write", "rename", "delete", "execute", "observe"]] = Field(default_factory=list)


class ServiceActivityQuery(ActivityQueryBase):
    activity_type: Literal["service"] = "service"
    service_refs: list[str] = Field(default_factory=list)
    operations: list[Literal["define", "enable", "disable", "start", "stop"]] = Field(default_factory=list)


class PackageActivityQuery(ActivityQueryBase):
    activity_type: Literal["package"] = "package"
    package_refs: list[str] = Field(default_factory=list)
    file_refs: list[str] = Field(default_factory=list)


class AssetActivityQuery(ActivityQueryBase):
    activity_type: Literal["asset"] = "asset"
    asset_refs: list[str] = Field(default_factory=list)


class ExtensionActivityQuery(ActivityQueryBase):
    activity_type: Literal["extension"] = "extension"
    extension_schemas: list[str] = Field(default_factory=list)


ActivityQuery = Annotated[
    ProcessActivityQuery
    | NetworkActivityQuery
    | SocketActivityQuery
    | FileActivityQuery
    | ServiceActivityQuery
    | PackageActivityQuery
    | AssetActivityQuery
    | ExtensionActivityQuery,
    Field(discriminator="activity_type"),
]
