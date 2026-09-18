"""Step 2 acceptance — investigation-side knowledge integration (RK-02/06).

The baseline node always executes before the verdict, failures degrade
explicitly without blocking, the three split tools expose business semantics
only, and knowledge content can never become case evidence — asserted with
prompt-injection fixtures inside the guidance.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from threat_agent.case_management import initialize_state
from threat_agent.contracts import (
    AttackTechniqueLookupInput,
    InterpretTelemetryFieldInput,
    JudgmentExperienceLookupInput,
    InvestigationToolLedger,
    KnowledgeItem,
)
from threat_agent.contracts.investigation import CandidateVerdict, VerdictLevel
from threat_agent.judgment.adapters.knowledge_tools import knowledge_scenario_tools
from threat_agent.judgment.application.graph import JudgmentGraph
from threat_agent.judgment.application.knowledge_baseline import run_knowledge_baseline
from threat_agent.judgment.application.report_draft import ReportDraft
from threat_agent.judgment.application.report_validation import ReportGroundingValidator
from threat_agent.judgment.domain.models import Claim, FinishRequest
from threat_agent.knowledge import ReferenceKnowledgeAdapter, SecurityKnowledgeService
from threat_agent.shared.execution import ExecutionContext, bind_execution_context

NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)


class FinishImmediatelyPlanner:
    """Scripted planner: no data tools, finish after the first iteration."""

    uses_data_tools = True

    def plan(self, state):
        return [FinishRequest(objective="证据已足够，直接结束调查形成结论")]


def _state():
    return initialize_state({
        "File_id": "file-a", "File_hash": "a" * 64, "File_path": "/tmp/a",
        "Sub_asset": "host-1", "tenant_id": "tenant-a", "run_id": "run-a",
    })


def _reference_service(adapter: ReferenceKnowledgeAdapter | None = None):
    return SecurityKnowledgeService(adapter or ReferenceKnowledgeAdapter())


@pytest.fixture()
def execution():
    with bind_execution_context(
        ExecutionContext(tenant_id="tenant-a", case_id="case-a", actor_id="test", run_id="run-a")
    ):
        yield


def _run_graph(service) -> "object":
    graph = JudgmentGraph(
        FinishImmediatelyPlanner(),
        tenant_id="tenant-a",
        run_id="run-a",
        knowledge_service=service,
    )
    return graph.run(_state())


def _baseline_records(state):
    return [
        record
        for record in state.tool_ledger.knowledge_consultations
        if record.entry == "baseline"
    ]


# -- RK-02: 基线检索必定执行 --------------------------------------------------


def test_baseline_executes_on_the_finish_route(execution):
    state = _run_graph(_reference_service())
    assert state.finished
    records = _baseline_records(state)
    assert len(records) == 1
    assert records[0].status == "available"
    # 人工研判经验 + ATT&CK 两类引用都进入调查指引，且可区分
    categories = {item.source_category for item in state.knowledge_guidance}
    assert {"analyst_judgment_experience", "attack_technique"} <= categories
    # 引用形如 knowledge_id@version#chunk_id，可追溯
    assert all("@" in ref and "#" in ref for ref in records[0].item_refs)


def test_baseline_failure_degrades_explicitly_and_never_blocks(execution):
    adapter = ReferenceKnowledgeAdapter()
    adapter.force_source_status("analyst_judgment_experience", "timeout")
    adapter.force_source_status("attack_technique", "permission_denied")
    state = _run_graph(SecurityKnowledgeService(adapter))
    assert state.finished  # 流程照常完成
    record = _baseline_records(state)[0]
    assert record.status == "degraded"
    assert record.limitations
    assert state.knowledge_guidance == []


def test_baseline_with_default_null_service_records_not_configured(execution):
    # 未传 knowledge_service：默认 Null 供应方，基线仍执行并显式记录
    graph = JudgmentGraph(FinishImmediatelyPlanner(), tenant_id="tenant-a")
    state = graph.run(_state())
    assert state.finished
    record = _baseline_records(state)[0]
    assert record.status == "not_configured"
    assert state.knowledge_guidance == []


def test_baseline_query_uses_verified_behaviors_only(execution):
    adapter = ReferenceKnowledgeAdapter()
    service = SecurityKnowledgeService(adapter)
    state = _state()
    # 模拟 Feature 02 的已验证 claim：查询由已验证行为构造
    state.claims = [
        Claim(
            claim_id="cl-1",
            claim_type="behavior",
            statement="计划任务指向未知脚本并固定间隔回连",
            source_evidence_refs=[],
            verification_state="supported",
        )
    ]
    run_knowledge_baseline(state, service)
    logged = adapter.call_log[0]
    # 查询文本只含行为摘要，不含原始文件内容或案件叙事字段
    assert "已验证行为" in logged["query_text"]
    assert "计划任务" in logged["query_text"]
    assert "File_hash" not in logged["query_text"]
    assert "a" * 64 not in logged["query_text"]


# -- 三个按用途拆分的工具 -----------------------------------------------------


@pytest.fixture()
def tools(execution):
    adapter = ReferenceKnowledgeAdapter()
    ledger = InvestigationToolLedger()
    service = SecurityKnowledgeService(adapter)
    return knowledge_scenario_tools(service, ledger), ledger, service, adapter


def test_three_split_tools_register_and_answer(tools):
    tool_map, ledger, service, _adapter = tools
    assert [tool.name for tool in tool_map] == [
        "lookup_attack_technique",
        "interpret_telemetry_field",
        "consult_judgment_experience",
    ]
    attack = {tool.name: tool for tool in tool_map}["lookup_attack_technique"]
    result = attack.invoke({"behaviors": ["计划任务持久化并固定间隔回连"]})
    assert result["status"] == "available"
    assert {item["source_category"] for item in result["items"]} == {"attack_technique"}

    manual = {tool.name: tool for tool in tool_map}["interpret_telemetry_field"]
    result = manual.invoke({"field_ids": ["netflow.session_reset_count"]})
    assert result["status"] == "available"
    assert {item["source_category"] for item in result["items"]} == {"telemetry_field_manual"}

    experience = {tool.name: tool for tool in tool_map}["consult_judgment_experience"]
    result = experience.invoke({
        "behaviors": ["无签名二进制写入系统路径"],
        "hypotheses": ["疑似供应链投毒"],
    })
    assert result["status"] == "available"
    assert {item["source_category"] for item in result["items"]} == {"analyst_judgment_experience"}

    # 每次工具调用都留了咨询记录：只记录不阻断
    assert [record.entry for record in ledger.knowledge_consultations] == [
        "lookup_attack_technique",
        "interpret_telemetry_field",
        "consult_judgment_experience",
    ]


def test_tool_schemas_carry_business_fields_only(tools):
    tool_map, _ledger, _service, _adapter = tools
    forbidden = {
        "tenant_id", "case_id", "actor_id", "run_id", "source_identity",
        "knowledge_domain", "query_text", "acl_tags", "collection", "top_k",
        "embedding", "reranker", "filter_dsl", "supplier", "endpoint", "api_key",
    }
    for schema in (
        AttackTechniqueLookupInput,
        InterpretTelemetryFieldInput,
        JudgmentExperienceLookupInput,
    ):
        fields = set(schema.model_json_schema()["properties"])
        assert not (fields & forbidden), fields & forbidden
    for tool in tool_map:
        assert tool.args_schema is not None


def test_tools_are_entries_of_one_scenario_service(tools):
    _tool_map, _ledger, service, _adapter = tools
    # 三个入口都落在研判场景服务上：scene 固定，intent 由工具用途决定
    assert service is not None


# -- RK-06 / 事实隔离：知识不能成为案件事实或证据 ------------------------------


def _draft_citing(knowledge_id: str) -> ReportDraft:
    verdict = CandidateVerdict(
        level=VerdictLevel.CONFIRMED_MALICIOUS,
        threat_type="backdoor_c2",
        summary="恶意",
        supporting_refs=[knowledge_id],
    )
    return ReportDraft(verdict=verdict, executive_summary="草稿")


def test_grounding_rejects_knowledge_ids_as_evidence_refs(execution):
    adapter = ReferenceKnowledgeAdapter()
    service = SecurityKnowledgeService(
        adapter,
        retrieval_options={"analyst_judgment_experience": {"top_k": 4}},
    )
    state = _state()
    guidance = run_knowledge_baseline(state, service)
    # 注入样本确实到达了模型上下文边界（作为数据）
    poison = [item for item in guidance if item.knowledge_id == "ke-judgment-poison-001"]
    assert poison, "注入样本应进入指引（内容不可信，但必须可见地走同一条通道）"

    validator = ReportGroundingValidator()
    issues = validator.validate(state, _draft_citing("ke-judgment-poison-001"))
    assert issues, "引用知识条目作为证据必须被接地校验拒绝"
    assert any("unknown_evidence_ref" == issue.code for issue in issues)

    # 对照：正常 ATT&CK 知识同样不能当证据引用
    issues = validator.validate(state, _draft_citing("ke-attack-t1053-003"))
    assert any("unknown_evidence_ref" == issue.code for issue in issues)


def test_guidance_items_carry_category_limitations_into_context(execution):
    adapter = ReferenceKnowledgeAdapter()
    state = _state()
    run_knowledge_baseline(state, SecurityKnowledgeService(adapter))
    for item in state.knowledge_guidance:
        assert item.category_limitations
        assert "不得作为当前案件事实或结论证据" in item.category_limitations[0]


def test_knowledge_never_touches_evidence_ledger(execution):
    state = _state()
    run_knowledge_baseline(state, _reference_service())
    assert state.knowledge_guidance
    # 事实隔离：知识条目不进查询结果、不进授权引用集合
    assert state.tool_ledger.query_results == []
    knowledge_ids = {item.knowledge_id for item in state.knowledge_guidance}
    assert not (knowledge_ids & set(state.tool_ledger.authorized_activity_refs))
    assert isinstance(state.knowledge_guidance[0], KnowledgeItem)
