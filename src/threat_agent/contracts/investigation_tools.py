from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from ..shared import StrictModel
from .activity import EntityIdentity, NormalizedActivity, ObservedRelation
from .data_boundary import ActivityQueryResult
from .evidence import Scope
from .knowledge import KnowledgeConsultationStatus, KnowledgeIntent


InvestigationToolName = Literal[
    "query_process_activities",
    "query_network_activities",
    "query_socket_activities",
    "query_file_activities",
    "query_service_activities",
    "query_package_activities",
    "query_asset_activities",
    "explore_entity",
    "get_raw_records",
    "calculate_activity_metrics",
]

BoundaryErrorCode = Literal[
    "single_host_required",
    "host_out_of_scope",
    "time_out_of_scope",
    "domain_out_of_scope",
    "entity_not_authorized",
    "reference_not_authorized",
]


class BoundaryDenied(StrictModel):
    """Structured pre-/post-execution boundary rejection.

    Carries identifiers only; the content of unauthorized objects must never
    enter events, traces or the model context.
    """

    code: BoundaryErrorCode
    tool_name: str
    message: str
    host_refs: list[str] = Field(default_factory=list)
    reference_ids: list[str] = Field(default_factory=list)


class ToolRuntimeContext(StrictModel):
    tenant_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    scope: Scope


class DomainActivityQueryInput(StrictModel):
    """活动查询的通用字段；具体领域子类补充各自专属过滤字段。

    ``activity_type`` 由工具名固定，不出现在任何查询参数里。
    """

    host_refs: list[str] = Field(default_factory=list, description="按主机引用过滤")
    entity_refs: list[str] = Field(default_factory=list, description="按实体引用过滤")
    start_time: datetime | None = Field(default=None, description="查询时间下界（含）")
    end_time: datetime | None = Field(default=None, description="查询时间上界（含）")
    source_event_types: list[str] = Field(default_factory=list, description="按来源事件类型过滤")
    cursor: str | None = Field(default=None, description="分页游标，取上次结果的 next_cursor")
    limit: int = Field(default=200, ge=1, le=1000, description="返回条数上限")

    @model_validator(mode="after")
    def validate_time_range(self) -> "DomainActivityQueryInput":
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValueError("start_time cannot be after end_time")
        return self


class ProcessActivitiesInput(DomainActivityQueryInput):
    process_refs: list[str] = Field(default_factory=list, description="按进程引用过滤")
    operations: list[Literal["create", "execute", "terminate"]] = Field(
        default_factory=list, description="进程操作：create/execute/terminate"
    )
    executable: str | None = Field(default=None, description="按可执行文件路径过滤")


class NetworkActivitiesInput(DomainActivityQueryInput):
    process_refs: list[str] = Field(default_factory=list, description="按进程引用过滤")
    endpoint_refs: list[str] = Field(default_factory=list, description="按目标端点引用过滤")
    protocols: list[str] = Field(default_factory=list, description="按协议过滤，如 tcp/udp")


class SocketActivitiesInput(DomainActivityQueryInput):
    process_refs: list[str] = Field(default_factory=list, description="按进程引用过滤")
    socket_refs: list[str] = Field(default_factory=list, description="按 socket 引用过滤")


class FileActivitiesInput(DomainActivityQueryInput):
    file_refs: list[str] = Field(default_factory=list, description="按文件引用过滤")
    process_refs: list[str] = Field(default_factory=list, description="按进程引用过滤")
    operations: list[Literal["create", "write", "rename", "delete", "execute", "observe"]] = Field(
        default_factory=list, description="文件操作"
    )


class ServiceActivitiesInput(DomainActivityQueryInput):
    service_refs: list[str] = Field(default_factory=list, description="按服务引用过滤")
    operations: list[Literal["define", "enable", "disable", "start", "stop"]] = Field(
        default_factory=list, description="服务操作"
    )


class PackageActivitiesInput(DomainActivityQueryInput):
    package_refs: list[str] = Field(default_factory=list, description="按软件包引用过滤")
    file_refs: list[str] = Field(default_factory=list, description="按文件引用过滤")


class AssetActivitiesInput(DomainActivityQueryInput):
    asset_refs: list[str] = Field(default_factory=list, description="按资产引用过滤")


class ExploreEntityInput(StrictModel):
    entity_ref: str = Field(min_length=1)
    include: list[Literal["identity", "relations", "timeline"]] = Field(
        default_factory=lambda: ["identity", "relations", "timeline"]
    )
    relation_direction: Literal["inbound", "outbound", "both"] = "both"
    start_time: datetime | None = None
    end_time: datetime | None = None
    cursor: str | None = None
    limit: int = Field(default=200, ge=1, le=1000)


class OutOfScopeRelationClue(StrictModel):
    """Minimal cross-host relation clue: identifiers and reason only."""

    relation_id: str
    other_endpoint_ref: str
    reason: Literal["host_out_of_scope"] = "host_out_of_scope"


class EntityExplorationResult(StrictModel):
    identity: EntityIdentity | None = None
    resolved_relations: list[ObservedRelation] = Field(default_factory=list)
    candidate_relations: list[ObservedRelation] = Field(default_factory=list)
    out_of_scope_relations: list[OutOfScopeRelationClue] = Field(default_factory=list)
    timeline: list[NormalizedActivity] = Field(default_factory=list)
    returned_count: int = Field(ge=0)
    next_cursor: str | None = None


class GetRawRecordsInput(StrictModel):
    activity_refs: list[str] = Field(
        min_length=1, max_length=10, description="本次运行中活动查询返回的活动 ID（形如 activity-raw-...，即上一步工具返回里的 evidence_ids）。案件上下文中的实体 ID（形如 process:host:pid:start）是上游线索、不是活动，填在这里会被边界拒绝。",
    )
    field_paths: list[str] = Field(
        default_factory=list, max_length=20,
        description="要提取的字段路径。原始记录是事件信封（event_id/event_type/observed_at/"
        "source_system/data 等），业务字段位于 data 下；直接写字段名（如 remote_ip）"
        "会自动在 data 下查找，也可显式写 data.remote_ip",
    )
    max_records: int = Field(default=10, ge=1, le=10)


class RawRecordView(StrictModel):
    activity_ref: str
    raw_record_ref: str
    source_system: str
    source_record_id: str
    observed_at: datetime
    payload: dict[str, Any]


class RawRecordResult(StrictModel):
    records: list[RawRecordView] = Field(default_factory=list)
    truncated: bool = False


class CalculateActivityMetricsInput(StrictModel):
    operation: Literal[
        "process_tree", "connection_pattern", "transfer_summary", "file_change_summary"
    ]
    activity_refs: list[str] = Field(
        min_length=1, max_length=1000, description="本次运行中活动查询返回的活动 ID（形如 activity-raw-...，即上一步工具返回里的 evidence_ids）。案件上下文中的实体 ID（形如 process:host:pid:start）是上游线索、不是活动，填在这里会被边界拒绝。",
    )
    parameters: dict[str, Any] = Field(default_factory=dict)


class ActivityMetricResult(StrictModel):
    operation: str
    activity_refs: list[str]
    metrics: dict[str, Any]
    limitations: list[str] = Field(default_factory=list)


# -- 知识工具（按用途拆分的研判场景服务入口） ---------------------------------
#
# 三个工具是同一场景服务的不同入口：参数只有业务语义，不含知识源、检索
# 参数或授权信息（RK-01）。知识内容只进入模型上下文作指引，不进入
# Evidence/Fact/Verdict（事实隔离）。


KnowledgeToolName = Literal[
    "lookup_attack_technique",
    "interpret_telemetry_field",
    "consult_judgment_experience",
]


class AttackTechniqueLookupInput(StrictModel):
    """查询 ATT&CK 技术：按已观察到的行为描述做攻击技术映射。"""

    behaviors: list[str] = Field(min_length=1, max_length=20, description="已观察到的行为描述")


class InterpretTelemetryFieldInput(StrictModel):
    """解释告警/日志字段：按字段名或告警类型查询遥测语义。"""

    field_ids: list[str] = Field(min_length=1, max_length=20, description="待解释的字段名或告警类型标识")


class JudgmentExperienceLookupInput(StrictModel):
    """查询研判经验：按行为与待验证假设查询历史研判做法。"""

    behaviors: list[str] = Field(default_factory=list, max_length=20, description="已验证的行为描述")
    hypotheses: list[str] = Field(default_factory=list, max_length=20, description="待验证的假设")


class KnowledgeConsultationRecord(StrictModel):
    """结案知识咨询记录：只记录不阻断，凭引用可追溯（设计 §5）。

    ``query_id`` 是审计关联键：供应方调用明细留在适配层，凭它关联（设计 §7-4）。
    """

    consultation_id: str = Field(min_length=1)
    query_id: str = Field(min_length=1)
    entry: Literal["baseline", KnowledgeToolName]
    intent: KnowledgeIntent
    status: KnowledgeConsultationStatus
    item_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class InvestigationToolTrace(StrictModel):
    sequence: int = Field(ge=1)
    tool_name: InvestigationToolName
    arguments: dict[str, Any]
    result_type: str
    result: dict[str, Any]
    tool_call_id: str | None = None
    model_message: dict[str, Any] = Field(default_factory=dict)


class InvestigationToolLedger(StrictModel):
    query_results: list[ActivityQueryResult] = Field(default_factory=list)
    entity_results: list[EntityExplorationResult] = Field(default_factory=list)
    raw_record_results: list[RawRecordResult] = Field(default_factory=list)
    metric_results: list[ActivityMetricResult] = Field(default_factory=list)
    traces: list[InvestigationToolTrace] = Field(default_factory=list)
    knowledge_consultations: list[KnowledgeConsultationRecord] = Field(default_factory=list)
    authorized_activity_refs: list[str] = Field(default_factory=list)
    authorized_entity_refs: list[str] = Field(default_factory=list)
