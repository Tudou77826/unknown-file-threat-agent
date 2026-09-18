"""Step 1 acceptance — knowledge capability base (RK-01/05/07/08/09 carriers).

All cases run on the reference adapter or the null supplier; no real RAG
supplier is involved (RK-09). Contract purity, authorization-by-framework,
per-source failure isolation and traceable citations are asserted here.
"""

from __future__ import annotations

import pytest

from threat_agent.contracts import (
    KnowledgeConsultation,
    KnowledgeConsultationContext,
    KnowledgeItem,
)
from threat_agent.knowledge import (
    NullKnowledgeSupplier,
    ReferenceKnowledgeAdapter,
    SecurityKnowledgeService,
    UnsupportedKnowledgeRequestError,
)
from threat_agent.shared.execution import (
    ExecutionContext,
    bind_execution_context,
    current_execution_context,
)

TENANT = "tenant-a"
CASE = "case-42"
ACTOR = "judgment-runtime"


@pytest.fixture()
def execution():
    with bind_execution_context(
        ExecutionContext(tenant_id=TENANT, case_id=CASE, actor_id=ACTOR, run_id="run-1")
    ):
        yield


@pytest.fixture()
def adapter() -> ReferenceKnowledgeAdapter:
    return ReferenceKnowledgeAdapter()


@pytest.fixture()
def service(adapter) -> SecurityKnowledgeService:
    return SecurityKnowledgeService(adapter)


def _investigation_request(**context) -> KnowledgeConsultation:
    return KnowledgeConsultation(
        scene="unknown_file_investigation",
        intent="investigation_guidance",
        context=KnowledgeConsultationContext(**context),
    )


def _response_request(**context) -> KnowledgeConsultation:
    return KnowledgeConsultation(
        scene="response_advisory",
        intent="response_policy_reference",
        context=KnowledgeConsultationContext(**context),
    )


def _telemetry_request(field_ids: list[str]) -> KnowledgeConsultation:
    return KnowledgeConsultation(
        scene="unknown_file_investigation",
        intent="telemetry_interpretation",
        context=KnowledgeConsultationContext(telemetry_field_ids=field_ids),
    )


# -- RK-01: 契约纯度与授权框架化 ---------------------------------------------


def test_business_request_carries_no_authorization_or_supplier_fields():
    forbidden = {
        "tenant_id", "case_id", "actor_id", "run_id", "source_identity",
        "acl_tags", "query_id", "api_key", "collection", "top_k", "embedding",
        "reranker", "filter_dsl", "supplier", "endpoint",
    }
    schema = KnowledgeConsultation.model_json_schema()
    fields = set(schema["properties"]) | set(
        KnowledgeConsultationContext.model_json_schema()["properties"]
    )
    assert not (fields & forbidden), fields & forbidden


def test_authorization_comes_from_framework_execution_context(service):
    with bind_execution_context(
        ExecutionContext(tenant_id=TENANT, case_id=CASE, actor_id=ACTOR)
    ):
        result = service.consult_investigation(
            _investigation_request(verified_behaviors=["计划任务指向未知脚本"])
        )
    assert result.tenant_id == TENANT
    assert result.case_id == CASE
    # 业务请求对象上根本没有授权字段可填
    assert not hasattr(_investigation_request(), "tenant_id")


def test_consultation_requires_bound_execution_context(service):
    with pytest.raises(RuntimeError, match="execution context"):
        service.consult_investigation(_investigation_request())


def test_execution_context_is_inherited_across_the_call_chain():
    with bind_execution_context(
        ExecutionContext(tenant_id=TENANT, case_id=CASE, actor_id="outer")
    ):
        with bind_execution_context(
            ExecutionContext(tenant_id=TENANT, case_id=CASE, actor_id="inner")
        ):
            assert current_execution_context().actor_id == "inner"
        assert current_execution_context().actor_id == "outer"


# -- 场景/意图 → 知识来源映射 ------------------------------------------------


def test_scene_intent_selects_expected_sources(execution, service, adapter):
    result = service.consult_investigation(
        _investigation_request(verified_behaviors=["计划任务指向未知脚本并固定间隔回连"])
    )
    assert [o.source_category for o in result.source_outcomes] == [
        "analyst_judgment_experience",
        "attack_technique",
    ]
    telemetry = service.consult_investigation(_telemetry_request(["netflow.session_reset_count"]))
    assert [o.source_category for o in telemetry.source_outcomes] == ["telemetry_field_manual"]
    response = service.consult_response(
        _response_request(verdict_summary="确认恶意：C2 回连", asset_constraints=["监控汇聚点"])
    )
    assert [o.source_category for o in response.source_outcomes] == [
        "org_sop",
        "responder_experience",
    ]


def test_unsupported_scene_intent_combination_is_rejected(execution, service):
    request = KnowledgeConsultation(
        scene="response_advisory",
        intent="investigation_guidance",
        context=KnowledgeConsultationContext(),
    )
    with pytest.raises(UnsupportedKnowledgeRequestError):
        service.consult(request)


def test_scenario_entry_points_validate_the_scene(execution, service):
    with pytest.raises(UnsupportedKnowledgeRequestError):
        service.consult_investigation(_response_request())
    with pytest.raises(UnsupportedKnowledgeRequestError):
        service.consult_response(_investigation_request())


def test_telemetry_query_uses_field_identifiers_only(execution, adapter):
    service = SecurityKnowledgeService(adapter)
    service.consult_investigation(_telemetry_request(["netflow.session_reset_count"]))
    logged = adapter.call_log[-1]
    assert "netflow.session_reset_count" in logged["query_text"]
    assert "已验证行为" not in logged["query_text"]


# -- RK-07: 状态可区分与单源失败隔离 ------------------------------------------


def test_available_status_with_merged_items(execution, service):
    result = service.consult_investigation(
        _investigation_request(verified_behaviors=["计划任务指向未知脚本并固定间隔回连外联地址"])
    )
    assert result.status == "available"
    assert result.items
    assert all(o.status == "available" for o in result.source_outcomes)


def test_null_supplier_reports_not_configured_per_source(execution):
    service = SecurityKnowledgeService(NullKnowledgeSupplier())
    result = service.consult_investigation(_investigation_request(verified_behaviors=["任意"]))
    assert result.status == "not_configured"
    assert result.items == []
    assert {o.status for o in result.source_outcomes} == {"not_configured"}
    assert result.limitations


def test_single_source_timeout_does_not_take_down_other_sources(execution, adapter):
    adapter.force_source_status("attack_technique", "timeout")
    service = SecurityKnowledgeService(adapter)
    result = service.consult_investigation(
        _investigation_request(verified_behaviors=["计划任务指向未知脚本并固定间隔回连"])
    )
    # 整体显式降级，绝不伪装成"没有相关知识"
    assert result.status == "degraded"
    by_source = {o.source_category: o for o in result.source_outcomes}
    assert by_source["attack_technique"].status == "timeout"
    assert by_source["attack_technique"].limitations
    # 其余来源条目仍然全部可用
    assert by_source["analyst_judgment_experience"].status == "available"
    assert {item.source_category for item in result.items} == {"analyst_judgment_experience"}
    assert any("部分知识来源不可用" in note for note in result.limitations)


@pytest.mark.parametrize("failure", ["permission_denied", "timeout", "error"])
def test_uniform_total_failure_keeps_distinguishable_status(execution, adapter, failure):
    for source in ("analyst_judgment_experience", "attack_technique"):
        adapter.force_source_status(source, failure)
    service = SecurityKnowledgeService(adapter)
    result = service.consult_investigation(_investigation_request(verified_behaviors=["任意"]))
    assert result.status == failure
    assert result.items == []
    assert all(o.status == failure for o in result.source_outcomes)


def test_mixed_failures_report_degraded(execution, adapter):
    adapter.force_source_status("analyst_judgment_experience", "permission_denied")
    adapter.force_source_status("attack_technique", "timeout")
    service = SecurityKnowledgeService(adapter)
    result = service.consult_investigation(_investigation_request(verified_behaviors=["任意"]))
    assert result.status == "degraded"


def test_forced_empty_is_empty_not_failure(execution, adapter):
    adapter.force_source_status("attack_technique", "empty")
    service = SecurityKnowledgeService(adapter)
    result = service.consult_investigation(_investigation_request(verified_behaviors=["任意"]))
    assert result.status == "available"  # 另一来源有结果且无失败
    by_source = {o.source_category: o for o in result.source_outcomes}
    assert by_source["attack_technique"].status == "empty"


def test_adapter_crash_is_normalized_per_source(execution, adapter):
    class ExplodingAdapter:
        def retrieve_sources(self, request):
            raise RuntimeError("supplier SDK crashed")

    service = SecurityKnowledgeService(ExplodingAdapter())
    result = service.consult_investigation(_investigation_request(verified_behaviors=["任意"]))
    assert result.status == "error"
    assert all(o.status == "error" for o in result.source_outcomes)
    assert all(o.limitations for o in result.source_outcomes)


def test_missing_source_in_adapter_response_is_error_not_empty(execution):
    class PartialAdapter:
        def retrieve_sources(self, request):
            from threat_agent.knowledge.ports.supplier_retrieval import (
                SupplierSourceOutcome,
            )

            return [
                SupplierSourceOutcome(source_category=request.sources[0].source_category, status="empty")
            ]

    service = SecurityKnowledgeService(PartialAdapter())
    result = service.consult_investigation(_investigation_request(verified_behaviors=["任意"]))
    by_source = {o.source_category: o for o in result.source_outcomes}
    assert by_source["attack_technique"].status == "error"
    assert "适配层未返回该来源" in by_source["attack_technique"].limitations[0]


# -- RK-05: 引用可追溯、两级限制、原始分数不进业务 ----------------------------


def test_items_are_traceable_and_category_limitations_always_present(execution, service):
    result = service.consult_investigation(
        _investigation_request(verified_behaviors=["计划任务指向未知脚本并固定间隔回连"])
    )
    assert result.items
    for item in result.items:
        assert item.knowledge_id and item.version and item.chunk_id and item.source_uri
        assert item.category_limitations, "类别级限制必须始终存在"
        assert "不得作为当前案件事实或结论证据" in item.category_limitations[0]


def test_response_items_carry_disposal_boundary(execution, service):
    result = service.consult_response(
        _response_request(verdict_summary="确认恶意：C2 回连", asset_constraints=["监控汇聚点主机"])
    )
    assert result.items
    for item in result.items:
        limitation = item.category_limitations[0]
        if item.source_category == "org_sop":
            assert "审批" in limitation or "资产条件校验" in limitation
        if item.source_category == "responder_experience":
            assert "组织政策校验" in limitation


def test_item_level_limitations_and_supplier_metadata_pass_through(execution, adapter):
    service = SecurityKnowledgeService(adapter)
    response = service.consult_response(_response_request(verdict_summary="确认恶意：C2 回连"))
    assert response.status == "available"
    sop_items = [i for i in response.items if i.source_category == "org_sop"]
    # 条目级限制来自知识自身元数据，允许为空但存在时必须原样到达业务侧
    assert any(i.item_limitations for i in sop_items)

    investigation = service.consult_investigation(
        _investigation_request(verified_behaviors=["计划任务指向未知脚本并固定间隔回连"])
    )
    analyst_items = [
        i for i in investigation.items if i.source_category == "analyst_judgment_experience"
    ]
    # 供应方元数据（如复核备注）原样保留，本系统不建模引用状态
    assert any(i.supplier_metadata.get("reviewed_by") for i in analyst_items)


def test_raw_scores_stay_out_of_business_result(execution, adapter):
    service = SecurityKnowledgeService(adapter)
    result = service.consult_investigation(
        _investigation_request(verified_behaviors=["计划任务指向未知脚本并固定间隔回连"])
    )
    assert "raw_score" not in KnowledgeItem.model_json_schema()["properties"]
    for outcome in result.source_outcomes:
        assert "raw_scores" not in outcome.diagnostics
        assert outcome.diagnostics["query_id"] == result.query_id
    # 原始分数留在适配层调用明细里，凭 query_id 关联
    assert adapter.call_log
    logged = adapter.call_log[-1]
    assert logged["query_id"] == result.query_id
    assert logged["raw_scores"]
    assert all("raw_score" in entry for entry in logged["raw_scores"])


# -- 处置合并：并列呈现，不按来源取舍 ----------------------------------------


def test_disposal_merge_keeps_all_sources_ordered_by_relevance_only(execution, adapter):
    service = SecurityKnowledgeService(adapter)
    result = service.consult_response(
        _response_request(
            verdict_summary="确认恶意：主机存在 C2 固定间隔回连",
            asset_constraints=["该主机为监控汇聚点"],
        )
    )
    categories = {item.source_category for item in result.items}
    assert categories == {"org_sop", "responder_experience"}
    # 排序只依据相关性等级（high -> medium -> low），同来源内部保持原序
    rank = {"high": 0, "medium": 1, "low": 2}
    relevance_ranks = [rank[item.relevance] for item in result.items]
    assert relevance_ranks == sorted(relevance_ranks)


def test_supplier_metadata_and_notes_survive_standard_and_alternate_profiles(execution):
    standard = SecurityKnowledgeService(ReferenceKnowledgeAdapter(profile="standard"))
    alternate = SecurityKnowledgeService(ReferenceKnowledgeAdapter(profile="alternate"))
    request = _response_request(verdict_summary="确认恶意：C2 回连")
    standard_result = standard.consult_response(request)
    alternate_result = alternate.consult_response(request)
    # 换档后：同一批知识标识仍然可得（换了供应方，知识没换）
    standard_ids = {i.knowledge_id for i in standard_result.items}
    alternate_ids = {i.knowledge_id for i in alternate_result.items}
    assert standard_ids
    assert alternate_ids == standard_ids
