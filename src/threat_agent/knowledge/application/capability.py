"""Security knowledge capability layer — decides "查什么", merges and isolates.

The capability layer turns a business consultation (scene + intent + minimized
context) into a per-source retrieval plan, hands it to the supplier-shaped
port, then standardizes the outcome: category-level usage limitations are
attached here (never delegated to a supplier), failures are isolated per
source, and the merged result is ordered by normalized relevance only — no
source is dropped, weighted or hidden because of its category.
"""

from __future__ import annotations

import uuid
from typing import Any, Iterable

from ...contracts import (
    KnowledgeConsultation,
    KnowledgeConsultationResult,
    KnowledgeIntent,
    KnowledgeItem,
    KnowledgeScene,
    KnowledgeSourceCategory,
    KnowledgeSourceOutcome,
    KnowledgeSourceStatus,
)
from ...shared.execution import current_execution_context
from ..ports.supplier_retrieval import (
    SupplierRetrievalPort,
    SupplierRetrievalRequest,
    SupplierSourceOutcome,
    SupplierSourceQuery,
)

# (scene, intent) -> knowledge sources the capability layer consults. The
# Agent never names sources; this table is the business meaning of "查什么".
# The two lookup intents are the split on-demand tool entries of the
# investigation scenario service (target design section 5); the coarse
# investigation_guidance intent is what the mandatory baseline node uses.
_SCENE_INTENT_SOURCES: dict[
    tuple[KnowledgeScene, KnowledgeIntent], tuple[KnowledgeSourceCategory, ...]
] = {
    ("unknown_file_investigation", "investigation_guidance"): (
        "analyst_judgment_experience",
        "attack_technique",
    ),
    ("unknown_file_investigation", "attack_technique_lookup"): (
        "attack_technique",
    ),
    ("unknown_file_investigation", "judgment_experience_lookup"): (
        "analyst_judgment_experience",
    ),
    ("unknown_file_investigation", "telemetry_interpretation"): (
        "telemetry_field_manual",
    ),
    ("response_advisory", "response_policy_reference"): (
        "org_sop",
        "responder_experience",
    ),
}

# Category-level usage limitations: attached by this layer, always present,
# never dependent on supplier metadata (target design section 4.2).
_CATEGORY_LIMITATIONS: dict[KnowledgeSourceCategory, tuple[str, ...]] = {
    "analyst_judgment_experience": ("仅作调查指引，不得作为当前案件事实或结论证据",),
    "attack_technique": ("仅作攻击行为映射参考，不得作为当前案件事实或结论证据",),
    "telemetry_field_manual": ("仅用于解读遥测字段语义，不改变遥测在证据模型中的地位",),
    "org_sop": ("处置动作仍须通过资产条件校验、处置策略与审批流程",),
    "responder_experience": ("仅供参考的历史处置经验，动作执行仍须满足组织政策校验",),
}

_RELEVANCE_RANK = {"high": 0, "medium": 1, "low": 2}

_FAILURE_STATUSES = frozenset({"permission_denied", "timeout", "error"})

_FAILURE_EXPLANATIONS = {
    "permission_denied": "知识源权限拒绝，未获得任何条目",
    "timeout": "知识源访问超时，未获得任何条目",
    "error": "知识源访问失败，未获得任何条目",
}


class UnsupportedKnowledgeRequestError(ValueError):
    """The scene/intent combination has no meaning in the business scenario."""


class SecurityKnowledgeService:
    """业务场景服务：研判与处置两个入口，共用一套输入/输出语义。"""

    def __init__(
        self,
        adapter: SupplierRetrievalPort,
        *,
        retrieval_options: dict[str, dict[str, Any]] | None = None,
        timeout_seconds: float = 10.0,
        identity: str = "knowledge-capability",
    ):
        self.adapter = adapter
        self.retrieval_options = retrieval_options or {}
        self.timeout_seconds = timeout_seconds
        self.identity = identity

    def catalog(self) -> dict[str, Any] | None:
        """Supplier catalog for operator surfaces; degraded to None on failure."""
        try:
            return self.adapter.catalog()
        except Exception:
            return None

    def consult_investigation(self, request: KnowledgeConsultation) -> KnowledgeConsultationResult:
        if request.scene != "unknown_file_investigation":
            raise UnsupportedKnowledgeRequestError(
                f"consult_investigation 接受未知文件研判场景，收到 {request.scene}"
            )
        return self._consult(request)

    def consult_response(self, request: KnowledgeConsultation) -> KnowledgeConsultationResult:
        if request.scene != "response_advisory":
            raise UnsupportedKnowledgeRequestError(
                f"consult_response 接受处置建议场景，收到 {request.scene}"
            )
        return self._consult(request)

    def consult(self, request: KnowledgeConsultation) -> KnowledgeConsultationResult:
        """按请求中的业务场景分发到对应场景服务入口。"""
        if request.scene == "unknown_file_investigation":
            return self.consult_investigation(request)
        return self.consult_response(request)

    # -- internals -----------------------------------------------------------

    def _consult(self, request: KnowledgeConsultation) -> KnowledgeConsultationResult:
        sources = _SCENE_INTENT_SOURCES.get((request.scene, request.intent))
        if sources is None:
            raise UnsupportedKnowledgeRequestError(
                f"业务场景与查询意图组合不存在知识来源映射：{request.scene}/{request.intent}"
            )

        execution = current_execution_context()
        query_id = f"kquery-{uuid.uuid4().hex[:12]}"
        supplier_request = SupplierRetrievalRequest(
            query_id=query_id,
            tenant_id=execution.tenant_id,
            case_id=execution.case_id,
            actor_id=execution.actor_id,
            timeout_seconds=self.timeout_seconds,
            sources=[
                SupplierSourceQuery(
                    source_category=source,
                    query_text=self._build_query_text(source, request),
                    options=dict(self.retrieval_options.get(source, {})),
                )
                for source in sources
            ],
        )

        outcomes = self._retrieve(supplier_request, sources)
        items = self._merge_items(outcomes)
        status, limitations = self._aggregate_status(outcomes)

        return KnowledgeConsultationResult(
            tenant_id=execution.tenant_id,
            case_id=execution.case_id,
            source_identity=self.identity,
            consultation_id=f"kcon-{uuid.uuid4().hex[:12]}",
            query_id=query_id,
            scene=request.scene,
            intent=request.intent,
            status=status,
            items=items,
            source_outcomes=[
                KnowledgeSourceOutcome(
                    source_category=outcome.source_category,
                    status=outcome.status,
                    item_count=len(outcome.items),
                    limitations=list(outcome.limitations),
                    diagnostics={
                        key: value
                        for key, value in outcome.diagnostics.items()
                        if key != "raw_scores"
                    }
                    | {"query_id": query_id},
                )
                for outcome in outcomes
            ],
            limitations=limitations,
        )

    def _retrieve(
        self,
        supplier_request: SupplierRetrievalRequest,
        sources: tuple[KnowledgeSourceCategory, ...],
    ) -> list[SupplierSourceOutcome]:
        """调用适配层；适配层整体异常时按源归一为 error，不让故障外溢。"""
        try:
            outcomes = self.adapter.retrieve_sources(supplier_request)
        except Exception as error:  # noqa: BLE001 — 单点故障按源归一，不阻断调用方
            return [
                SupplierSourceOutcome(
                    source_category=source,
                    status="error",
                    limitations=[f"适配层异常：{type(error).__name__}: {error}"],
                    diagnostics={"query_id": supplier_request.query_id},
                )
                for source in sources
            ]
        by_source = {outcome.source_category: outcome for outcome in outcomes}
        return [
            by_source.get(
                source,
                # 适配层漏报请求过的来源属于契约违约，按 error 处理——
                # 不能把"适配层没交代"伪装成"没有相关知识"。
                SupplierSourceOutcome(
                    source_category=source,
                    status="error",
                    limitations=["适配层未返回该来源的访问结果"],
                ),
            )
            for source in sources
        ]

    def _build_query_text(self, source: KnowledgeSourceCategory, request: KnowledgeConsultation) -> str:
        context = request.context
        if source == "telemetry_field_manual":
            # 遥测语义解释只依赖字段标识本身，不掺入案件叙事。
            parts = [f"字段标识: {value}" for value in context.telemetry_field_ids]
            return "; ".join(parts) if parts else "遥测字段语义解释"
        if request.scene == "response_advisory":
            parts = []
            if context.verdict_summary:
                parts.append(f"研判结论: {context.verdict_summary}")
            parts.extend(f"资产约束: {value}" for value in context.asset_constraints)
            parts.extend(f"已验证行为: {value}" for value in context.verified_behaviors)
            return "; ".join(parts) if parts else "处置政策与经验参考"
        parts = [f"已验证行为: {value}" for value in context.verified_behaviors]
        parts.extend(f"待验证假设: {value}" for value in context.open_hypotheses)
        return "; ".join(parts) if parts else "未知文件调查指引"

    def _merge_items(self, outcomes: Iterable[SupplierSourceOutcome]) -> list[KnowledgeItem]:
        """按源合并为调查/处置指引：全部合格结果进入合并，排序只依据相关性等级。

        同级内保持（来源顺序，条目顺序）的稳定次序——不引入来源级别的
        加权、丢弃或隐藏；条目级限制与供应方元数据原样保留。
        """
        ranked: list[tuple[tuple[int, int, int], KnowledgeItem]] = []
        for source_index, outcome in enumerate(outcomes):
            if outcome.status != "available":
                continue
            for item_index, item in enumerate(outcome.items):
                ranked.append(
                    (
                        (_RELEVANCE_RANK[item.relevance], source_index, item_index),
                        KnowledgeItem(
                            knowledge_id=item.knowledge_id,
                            version=item.version,
                            chunk_id=item.chunk_id,
                            source_category=outcome.source_category,
                            title=item.title,
                            summary=item.summary,
                            content=item.content,
                            source_uri=item.source_uri,
                            relevance=item.relevance,
                            category_limitations=list(
                                _CATEGORY_LIMITATIONS[outcome.source_category]
                            ),
                            item_limitations=list(item.item_limitations),
                            supplier_metadata=dict(item.supplier_metadata),
                        ),
                    )
                )
        ranked.sort(key=lambda entry: entry[0])
        return [item for _key, item in ranked]

    @staticmethod
    def _aggregate_status(
        outcomes: list[SupplierSourceOutcome],
    ) -> tuple[str, list[str]]:
        """整体状态聚合：失败与能力不足绝不伪装成"没有相关知识"。"""
        statuses = [outcome.status for outcome in outcomes]
        limitations: list[str] = []

        if not outcomes:
            return "not_configured", ["没有配置任何知识来源"]

        def note(outcome: SupplierSourceOutcome, fallback: str) -> str:
            return f"[{outcome.source_category}] " + (
                outcome.limitations[0] if outcome.limitations else fallback
            )

        failures = [status for status in statuses if status in _FAILURE_STATUSES]
        if failures:
            if len(failures) == len(statuses) and len(set(failures)) == 1:
                # 全部来源同一种失败：状态即该失败，明确可区分。
                failure = failures[0]
                limitations.extend(
                    note(outcome, _FAILURE_EXPLANATIONS[failure]) for outcome in outcomes
                )
                return failure, limitations
            # 部分失败：其余来源结果仍可用，整体显式降级标注。
            limitations.extend(
                note(outcome, _FAILURE_EXPLANATIONS[outcome.status])
                for outcome in outcomes
                if outcome.status in _FAILURE_STATUSES
            )
            limitations.append("部分知识来源不可用，结果基于其余来源生成")
            return "degraded", limitations

        not_configured = [
            outcome for outcome in outcomes if outcome.status == "not_configured"
        ]
        if not_configured:
            if all(outcome.status == "not_configured" for outcome in outcomes):
                limitations.extend(note(outcome, "该知识来源未配置") for outcome in outcomes)
                return "not_configured", limitations
            # 部分来源未配置：有能力缺口，整体降级并说明缺口。
            limitations.extend(note(outcome, "该知识来源未配置") for outcome in not_configured)
            limitations.append("部分知识来源未配置，结果基于已配置来源生成")
            return "degraded", limitations

        if any(outcome.items for outcome in outcomes):
            return "available", limitations
        return "empty", ["所有知识来源均无相关结果"]


def category_limitations_of(source: KnowledgeSourceCategory) -> tuple[str, ...]:
    """业务侧查询某来源类别的固定使用边界（供测试与审计使用）。"""
    return _CATEGORY_LIMITATIONS[source]


def sources_for(scene: KnowledgeScene, intent: KnowledgeIntent) -> tuple[KnowledgeSourceCategory, ...]:
    """业务侧查询某场景/意图映射的知识来源（供测试与编排使用）。"""
    sources = _SCENE_INTENT_SOURCES.get((scene, intent))
    if sources is None:
        raise UnsupportedKnowledgeRequestError(
            f"业务场景与查询意图组合不存在知识来源映射：{scene}/{intent}"
        )
    return sources
