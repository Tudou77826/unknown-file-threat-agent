from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from ..shared import StrictModel
from .common import ContractModel

# ---------------------------------------------------------------------------
# Target business contracts (Feature: security knowledge capability + RAG
# adapter, target design section 4). The Agent-facing request carries business
# semantics only: scene, intent and a minimized structured context.
# Authorization (tenant/case/actor) is carried by the framework execution
# context, never by these fields. Retrieval parameters (collection, top K,
# embedding, reranker, supplier-specific options) belong to the management
# plane and never appear here either.
# ---------------------------------------------------------------------------

KnowledgeScene = Literal["unknown_file_investigation", "response_advisory"]

KnowledgeIntent = Literal[
    "investigation_guidance",
    "attack_technique_lookup",
    "judgment_experience_lookup",
    "telemetry_interpretation",
    "response_policy_reference",
]

KnowledgeSourceCategory = Literal[
    "analyst_judgment_experience",
    "attack_technique",
    "telemetry_field_manual",
    "org_sop",
    "responder_experience",
]

KnowledgeConsultationStatus = Literal[
    "available",
    "empty",
    "not_configured",
    "permission_denied",
    "timeout",
    "degraded",
    "error",
]

KnowledgeSourceStatus = Literal[
    "available",
    "empty",
    "not_configured",
    "permission_denied",
    "timeout",
    "error",
]

KnowledgeRelevance = Literal["high", "medium", "low"]


class KnowledgeConsultationContext(StrictModel):
    """经最小化处理的安全上下文：只携带完成该次知识检索所需的结构化业务字段。"""

    verified_behaviors: list[str] = Field(default_factory=list, description="已验证行为")
    open_hypotheses: list[str] = Field(default_factory=list, description="待验证假设")
    telemetry_field_ids: list[str] = Field(
        default_factory=list, description="待解释的告警/日志字段标识或告警类型"
    )
    verdict_summary: str | None = Field(default=None, description="研判结论摘要（处置场景）")
    asset_constraints: list[str] = Field(default_factory=list, description="资产约束")


class KnowledgeConsultation(StrictModel):
    """面向 Agent 的知识咨询请求：只有业务语义字段。

    授权信息（租户、案件、调用身份）由框架执行上下文承载并全程继承，
    不在本契约中出现；知识库、检索与供应方参数由管理面配置维护。
    """

    scene: KnowledgeScene
    intent: KnowledgeIntent
    context: KnowledgeConsultationContext = Field(default_factory=KnowledgeConsultationContext)


class KnowledgeItem(StrictModel):
    """标准化知识条目：稳定标识加版本可事后追溯，供应方元数据原样保留。"""

    knowledge_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    chunk_id: str = Field(min_length=1)
    source_category: KnowledgeSourceCategory
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    content: str = Field(min_length=1)
    source_uri: str = Field(min_length=1)
    relevance: KnowledgeRelevance
    category_limitations: list[str] = Field(min_length=1)
    item_limitations: list[str] = Field(default_factory=list)
    supplier_metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeSourceOutcome(StrictModel):
    """按源保留的访问结果与限制说明：单源失败不影响其余来源的呈现。"""

    source_category: KnowledgeSourceCategory
    status: KnowledgeSourceStatus
    item_count: int = Field(ge=0)
    limitations: list[str] = Field(default_factory=list)
    diagnostics: dict[str, Any] = Field(default_factory=dict)


class KnowledgeConsultationResult(ContractModel):
    consultation_id: str = Field(min_length=1)
    query_id: str = Field(min_length=1)
    scene: KnowledgeScene
    intent: KnowledgeIntent
    status: KnowledgeConsultationStatus
    items: list[KnowledgeItem] = Field(default_factory=list)
    source_outcomes: list[KnowledgeSourceOutcome] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


def knowledge_item_ref(item: KnowledgeItem) -> str:
    """统一引用定位：knowledge_id@version#chunk_id（设计 §5）。"""

    return f"{item.knowledge_id}@{item.version}#{item.chunk_id}"
