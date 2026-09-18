"""RK-01..RK-09 acceptance suite (target design section 9).

One test per acceptance item, executed end-to-end on the behavior-controllable
reference adapter (RK-09); no real RAG supplier is involved. Run verbose to
produce the acceptance record:

    pytest tests/test_rk_acceptance.py -v
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from threat_agent.bootstrap.demo import build_knowledge_service
from threat_agent.bootstrap.settings import AppSettings
from threat_agent.case_management import initialize_state
from threat_agent.contracts import (
    AttackTechniqueLookupInput,
    InterpretTelemetryFieldInput,
    JudgmentResult,
    JudgmentExperienceLookupInput,
    KnowledgeConsultation,
    KnowledgeConsultationContext,
)
from threat_agent.contracts.investigation import CandidateVerdict, VerdictLevel
from threat_agent.judgment.adapters.knowledge_tools import knowledge_scenario_tools
from threat_agent.judgment.application.data_tool_planner import PLANNER_SYSTEM_PROMPT
from threat_agent.judgment.application.graph import JudgmentGraph
from threat_agent.judgment.application.report_draft import ReportDraft
from threat_agent.judgment.application.report_validation import ReportGroundingValidator
from threat_agent.judgment.domain.models import FinishRequest
from threat_agent.knowledge import (
    NullKnowledgeSupplier,
    ReferenceKnowledgeAdapter,
    SecurityKnowledgeService,
)
from threat_agent.response_advisory.application.planner import StructuredResponsePlanner
from threat_agent.response_advisory.domain.models import ResponseProposal
from threat_agent.shared.execution import ExecutionContext, bind_execution_context

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "threat_agent"


class FinishImmediatelyPlanner:
    uses_data_tools = True

    def plan(self, state):
        return [FinishRequest(objective="证据已足够，直接结束调查形成结论")]


def _state():
    return initialize_state({
        "File_id": "file-a", "File_hash": "a" * 64, "File_path": "/tmp/a",
        "Sub_asset": "host-1", "tenant_id": "tenant-a", "run_id": "run-a",
    })


def _judgment() -> JudgmentResult:
    return JudgmentResult(
        tenant_id="tenant-a",
        case_id="case-a",
        source_identity="acceptance",
        verdict=CandidateVerdict(
            level=VerdictLevel.CONFIRMED_MALICIOUS,
            threat_type="backdoor_c2",
            summary="计划任务持久化并固定间隔回连",
            supporting_refs=["act-c2-1"],
        ),
    )


def _investigation_request(**context) -> KnowledgeConsultation:
    return KnowledgeConsultation(
        scene="unknown_file_investigation",
        intent="investigation_guidance",
        context=KnowledgeConsultationContext(**context),
    )


@pytest.fixture()
def execution():
    with bind_execution_context(
        ExecutionContext(tenant_id="tenant-a", case_id="case-a", actor_id="acceptance")
    ):
        yield


# -- RK-01 请求契约与工具 Schema 纯度；授权由框架承载 -------------------------


def test_rk_01_business_surface_has_no_supplier_or_authorization_fields():
    forbidden = {
        "tenant_id", "case_id", "actor_id", "run_id", "source_identity",
        "acl_tags", "query_id", "api_key", "collection", "top_k", "embedding",
        "reranker", "filter_dsl", "supplier", "endpoint", "knowledge_domain",
    }
    for schema in (
        KnowledgeConsultation,
        KnowledgeConsultationContext,
        AttackTechniqueLookupInput,
        InterpretTelemetryFieldInput,
        JudgmentExperienceLookupInput,
    ):
        fields = set(schema.model_json_schema()["properties"])
        assert not (fields & forbidden), (schema.__name__, fields & forbidden)

    # 业务模块只消费能力层：judgment/response/case_management 不 import 适配器与 Port
    for package in ("judgment", "response_advisory", "case_management"):
        for path in (SRC_ROOT / package).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                target = None
                if isinstance(node, ast.ImportFrom) and node.module:
                    target = f"threat_agent.{node.module}" if node.level == 0 else None
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("threat_agent."):
                            target = alias.name
                if target and (
                    target.startswith("threat_agent.knowledge.adapters")
                    or target.startswith("threat_agent.knowledge.ports")
                ):
                    raise AssertionError(f"{package} imports knowledge internals: {target}")


def test_rk_01_authorization_is_bound_by_the_framework_only():
    service = SecurityKnowledgeService(ReferenceKnowledgeAdapter())
    with bind_execution_context(ExecutionContext("tenant-a", "case-a", "acceptance")):
        result = service.consult_investigation(
            _investigation_request(verified_behaviors=["计划任务持久化并固定间隔回连"])
        )
        assert result.tenant_id == "tenant-a" and result.case_id == "case-a"
    # 离开绑定作用域后无残留：没有绑定就没有知识调用（授权不可伪造）
    from threat_agent.shared.execution import try_current_execution_context

    assert try_current_execution_context() is None
    with pytest.raises(RuntimeError, match="execution context"):
        service.consult_investigation(_investigation_request(verified_behaviors=["x"]))


# -- RK-02 基线检索必定执行；三类知识入口可得；引用可区分 ---------------------


def test_rk_02_baseline_always_runs_and_three_entries_answer(execution):
    graph = JudgmentGraph(
        FinishImmediatelyPlanner(),
        tenant_id="tenant-a",
        knowledge_service=SecurityKnowledgeService(ReferenceKnowledgeAdapter()),
    )
    state = graph.run(_state())
    assert state.finished
    baseline = [
        r for r in state.tool_ledger.knowledge_consultations if r.entry == "baseline"
    ]
    assert len(baseline) == 1 and baseline[0].status == "available"
    categories = {item.source_category for item in state.knowledge_guidance}
    assert {"analyst_judgment_experience", "attack_technique"} <= categories
    assert all("@" in ref and "#" in ref for ref in baseline[0].item_refs)

    # 三个按用途拆分的入口：ATT&CK / 告警日志含义 / 研判经验
    ledger = state.tool_ledger
    service = SecurityKnowledgeService(ReferenceKnowledgeAdapter())
    tools = {tool.name: tool for tool in knowledge_scenario_tools(service, ledger)}
    attack = tools["lookup_attack_technique"].invoke({"behaviors": ["计划任务持久化"]})
    manual = tools["interpret_telemetry_field"].invoke(
        {"field_ids": ["behavior:persistence_service_created"]}
    )
    experience = tools["consult_judgment_experience"].invoke(
        {"behaviors": ["无签名二进制写入系统路径"]}
    )
    assert {i["source_category"] for i in attack["items"]} == {"attack_technique"}
    assert {i["source_category"] for i in manual["items"]} == {"telemetry_field_manual"}
    assert {i["source_category"] for i in experience["items"]} == {
        "analyst_judgment_experience"
    }


def test_rk_02_baseline_degrades_explicitly_without_blocking(execution):
    adapter = ReferenceKnowledgeAdapter()
    adapter.force_source_status("analyst_judgment_experience", "timeout")
    adapter.force_source_status("attack_technique", "timeout")
    graph = JudgmentGraph(
        FinishImmediatelyPlanner(),
        tenant_id="tenant-a",
        knowledge_service=SecurityKnowledgeService(adapter),
    )
    state = graph.run(_state())
    assert state.finished
    baseline = state.tool_ledger.knowledge_consultations[-1]
    assert baseline.entry == "baseline" and baseline.status == "timeout"
    assert baseline.limitations


# -- RK-03 处置结果全部如实呈现；最终约束不变 ---------------------------------


def test_rk_03_disposal_presents_all_sources_and_keeps_constraints(execution):
    from tests.test_knowledge_response import CapturingPlanner, _conservative_proposal
    from threat_agent.response_advisory.application.graph import ResponseGraph
    from threat_agent.response_advisory.domain.policy import validate_response_proposal

    planner = CapturingPlanner()
    graph = ResponseGraph(
        planner,
        knowledge_service=SecurityKnowledgeService(ReferenceKnowledgeAdapter()),
        max_iterations=1,
    )
    plan = graph.run(_judgment())
    knowledge = planner.seen[0]
    assert knowledge.status == "available"
    assert {item.source_category for item in knowledge.items} == {
        "org_sop",
        "responder_experience",
    }
    for item in knowledge.items:
        assert item.knowledge_id and item.version and item.chunk_id
    # 最终约束：保守建议照旧通过策略校验，处置校验未被知识放松
    assert validate_response_proposal(_judgment(), _conservative_proposal()) == []
    assert plan.status == "recommended"


# -- RK-04 更换供应方不触及业务面 ---------------------------------------------


def test_rk_04_supplier_swap_via_config_only(execution):
    standard = build_knowledge_service(
        AppSettings.load(
            environ={"KNOWLEDGE_ADAPTER": "reference", "KNOWLEDGE_REFERENCE_PROFILE": "standard"},
            env_file=Path("__no_such_env_file__"),
        )
    )
    alternate = build_knowledge_service(
        AppSettings.load(
            environ={"KNOWLEDGE_ADAPTER": "reference", "KNOWLEDGE_REFERENCE_PROFILE": "alternate"},
            env_file=Path("__no_such_env_file__"),
        )
    )
    request = KnowledgeConsultation(
        scene="response_advisory",
        intent="response_policy_reference",
        context=KnowledgeConsultationContext(verdict_summary="确认恶意：C2 回连"),
    )
    standard_result = standard.consult_response(request)
    alternate_result = alternate.consult_response(request)
    # 换了供应方档位：知识不换、业务面不变
    assert {i.knowledge_id for i in standard_result.items} == {
        i.knowledge_id for i in alternate_result.items
    }

    # 工具 Schema、系统提示词、场景编排与业务契约零改动（未按供应方分支）
    tools_a = knowledge_scenario_tools(standard, type("L", (), {"knowledge_consultations": []})())
    tools_b = knowledge_scenario_tools(alternate, type("L", (), {"knowledge_consultations": []})())
    assert [t.name for t in tools_a] == [t.name for t in tools_b]
    for a, b in zip(tools_a, tools_b):
        assert a.args_schema is b.args_schema
    assert "reference" not in PLANNER_SYSTEM_PROMPT.lower()
    assert "supplier" not in KnowledgeConsultation.model_json_schema()["properties"]


# -- RK-05 稳定引用与限制；原始分数不进业务 -----------------------------------


def test_rk_05_traceable_references_and_scores_stay_diagnostic(execution):
    adapter = ReferenceKnowledgeAdapter()
    service = SecurityKnowledgeService(adapter)
    result = service.consult_response(
        KnowledgeConsultation(
            scene="response_advisory",
            intent="response_policy_reference",
            context=KnowledgeConsultationContext(verdict_summary="确认恶意：C2 回连"),
        )
    )
    assert result.items
    for item in result.items:
        assert item.knowledge_id and item.version and item.chunk_id and item.source_uri
        assert item.category_limitations
    assert "raw_score" not in result.model_dump()["items"][0]
    for outcome in result.source_outcomes:
        assert "raw_scores" not in outcome.diagnostics
    # 原始分数在适配层明细里，凭 query_id 关联
    matched = [log for log in adapter.call_log if log["query_id"] == result.query_id]
    assert matched and any(log["raw_scores"] for log in matched)


# -- RK-06 ACL 前置过滤；注入内容改变不了系统边界 -----------------------------


def test_rk_06_tenant_restricted_item_never_reaches_other_tenants():
    with bind_execution_context(ExecutionContext("tenant-a", "case-a", "acceptance")):
        service = SecurityKnowledgeService(ReferenceKnowledgeAdapter())
        result = service.consult_response(
            KnowledgeConsultation(
                scene="response_advisory",
                intent="response_policy_reference",
                context=KnowledgeConsultationContext(verdict_summary="隔离核心交易主机"),
            )
        )
        ids = {item.knowledge_id for item in result.items}
        assert "ke-resp-tenantb-001" not in ids
        serialized = result.model_dump_json()
        assert "tenant-b 内部" not in serialized and "加急二级" not in serialized

    with bind_execution_context(ExecutionContext("tenant-b", "case-b", "acceptance")):
        result = service.consult_response(
            KnowledgeConsultation(
                scene="response_advisory",
                intent="response_policy_reference",
                context=KnowledgeConsultationContext(verdict_summary="隔离核心交易主机"),
            )
        )
        assert "ke-resp-tenantb-001" in {item.knowledge_id for item in result.items}


def test_rk_06_injected_knowledge_cannot_become_evidence(execution):
    adapter = ReferenceKnowledgeAdapter()
    service = SecurityKnowledgeService(
        adapter, retrieval_options={"analyst_judgment_experience": {"top_k": 4}}
    )
    state = _state()
    from threat_agent.judgment.application.knowledge_baseline import run_knowledge_baseline

    guidance = run_knowledge_baseline(state, service)
    assert any(i.knowledge_id == "ke-judgment-poison-001" for i in guidance)

    def draft_citing(ref: str) -> ReportDraft:
        return ReportDraft(
            verdict=CandidateVerdict(
                level=VerdictLevel.CONFIRMED_MALICIOUS,
                threat_type="backdoor_c2",
                summary="被注入样本要求的定性",
                supporting_refs=[ref],
            ),
            executive_summary="草稿",
        )

    issues = ReportGroundingValidator().validate(
        state, draft_citing("ke-judgment-poison-001")
    )
    assert issues and any(issue.code == "unknown_evidence_ref" for issue in issues)


# -- RK-07 状态可区分、单源失败隔离、失败不阻断 -------------------------------


@pytest.mark.parametrize(
    "forced",
    ["empty", "not_configured", "permission_denied", "timeout", "error"],
)
def test_rk_07_failure_states_distinguishable(execution, forced):
    adapter = ReferenceKnowledgeAdapter()
    adapter.force_source_status("attack_technique", forced)
    service = SecurityKnowledgeService(adapter)
    result = service.consult_investigation(
        _investigation_request(verified_behaviors=["计划任务持久化并回连"])
    )
    by_source = {o.source_category: o for o in result.source_outcomes}
    assert by_source["attack_technique"].status == forced
    if forced in {"permission_denied", "timeout", "error"}:
        assert result.status == "degraded"
        assert by_source["analyst_judgment_experience"].status == "available"
        assert {i.source_category for i in result.items} == {"analyst_judgment_experience"}
        assert any("部分知识来源不可用" in n for n in result.limitations)
    elif forced == "empty":
        assert result.status == "available"
    else:
        assert result.status == "degraded"  # 部分来源未配置同样显式降级


def test_rk_07_any_knowledge_failure_never_blocks_the_core_flow(execution):
    adapter = ReferenceKnowledgeAdapter()
    for source in ("analyst_judgment_experience", "attack_technique"):
        adapter.force_source_status(source, "error")
    graph = JudgmentGraph(
        FinishImmediatelyPlanner(),
        tenant_id="tenant-a",
        knowledge_service=SecurityKnowledgeService(adapter),
    )
    state = graph.run(_state())
    assert state.finished  # 基于安全遥测的核心流程照常完成


# -- RK-08 管理面配置承载，Agent 运行中不可改 ---------------------------------


def test_rk_08_supplier_selection_is_config_only():
    null_default = build_knowledge_service(
        AppSettings.load(environ={}, env_file=Path("__no_such_env_file__"))
    )
    assert isinstance(null_default.adapter, NullKnowledgeSupplier)
    reference = build_knowledge_service(
        AppSettings.load(
            environ={"KNOWLEDGE_ADAPTER": "reference"},
            env_file=Path("__no_such_env_file__"),
        )
    )
    assert isinstance(reference.adapter, ReferenceKnowledgeAdapter)
    # 配置对象不可变：运行中没有可篡改的配置面
    settings = AppSettings.load(environ={}, env_file=Path("__no_such_env_file__"))
    with pytest.raises(Exception):
        settings.knowledge.adapter = "reference"  # type: ignore[misc]


# -- RK-09 行为可控的参考适配器 -----------------------------------------------


def test_rk_09_reference_adapter_covers_all_simulated_behaviors(execution):
    adapter = ReferenceKnowledgeAdapter(profile="standard")
    adapter.force_source_status("telemetry_field_manual", "permission_denied")
    service = SecurityKnowledgeService(adapter)
    result = service.consult_investigation(
        KnowledgeConsultation(
            scene="unknown_file_investigation",
            intent="telemetry_interpretation",
            context=KnowledgeConsultationContext(
                telemetry_field_ids=["netflow.session_reset_count"]
            ),
        )
    )
    assert result.status == "permission_denied"
    adapter.clear_forced_statuses()
    result = service.consult_investigation(
        KnowledgeConsultation(
            scene="unknown_file_investigation",
            intent="telemetry_interpretation",
            context=KnowledgeConsultationContext(
                telemetry_field_ids=["netflow.session_reset_count"]
            ),
        )
    )
    assert result.status == "available"
    # 调用明细留适配层，含原始分数与供应方标识，凭 query_id 关联
    assert adapter.call_log and adapter.call_log[-1]["supplier_id"] == "reference-rag/standard"
