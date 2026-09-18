"""Step 3 acceptance — disposal-side knowledge via the capability layer (RK-03).

The fixed node before proposal generation consults the response scenario
service; every qualified item from every source reaches the planner labeled
and traceable, failures degrade explicitly without blocking, and the final
plan still passes the disposal policy validation untouched.
"""

from __future__ import annotations

import pytest

from threat_agent.contracts import (
    JudgmentResult,
    KnowledgeConsultationResult,
    ResponseAction,
)
from threat_agent.contracts.investigation import CandidateVerdict, VerdictLevel
from threat_agent.knowledge import (
    NullKnowledgeSupplier,
    ReferenceKnowledgeAdapter,
    SecurityKnowledgeService,
)
from threat_agent.response_advisory.application.graph import ResponseGraph
from threat_agent.response_advisory.application.planner import StructuredResponsePlanner
from threat_agent.response_advisory.domain.models import ResponseProposal
from threat_agent.response_advisory.domain.policy import validate_response_proposal
from threat_agent.shared.execution import ExecutionContext, bind_execution_context


class CapturingPlanner:
    """Scripted planner: records the knowledge it was handed, proposes one
    conservative manual-review action that passes disposal policy."""

    def __init__(self):
        self.seen: list[KnowledgeConsultationResult | None] = []

    def propose(self, judgment, knowledge, validation_errors, response_context=None):
        self.seen.append(knowledge)
        return ResponseProposal(
            actions=[
                ResponseAction(
                    action_id="act-review",
                    action_type="manual_review",
                    target_refs=["host-1"],
                    rationale="复核告警原文与样本",
                    judgment_refs=["act-c2-1"],
                    preconditions=["安全值班同事可接手"],
                    expected_impact="无系统影响，仅占用人工复核时间",
                    approval_class="none",
                    verification_steps=["复核结论回填到工单"],
                )
            ]
        )


def _judgment() -> JudgmentResult:
    return JudgmentResult(
        tenant_id="tenant-a",
        case_id="case-a",
        source_identity="test",
        verdict=CandidateVerdict(
            level=VerdictLevel.CONFIRMED_MALICIOUS,
            threat_type="backdoor_c2",
            summary="未知文件建立计划任务持久化并固定间隔回连 C2",
            supporting_refs=["act-c2-1"],
        ),
    )


@pytest.fixture()
def execution():
    with bind_execution_context(
        ExecutionContext(tenant_id="tenant-a", case_id="case-a", actor_id="test")
    ):
        yield


def _run(planner, service):
    graph = ResponseGraph(planner, knowledge_service=service, max_iterations=1)
    return graph.run(_judgment())


# -- 固定节点经能力层检索，全部合格结果并列到达 planner ----------------------


def test_fixed_node_delivers_merged_knowledge_to_planner(execution):
    planner = CapturingPlanner()
    plan = _run(planner, SecurityKnowledgeService(ReferenceKnowledgeAdapter()))
    assert planner.seen and planner.seen[0] is not None
    knowledge = planner.seen[0]
    assert knowledge.scene == "response_advisory"
    assert knowledge.status == "available"
    categories = {item.source_category for item in knowledge.items}
    # 政策与经验全部在场：并列呈现，不因来源丢弃、降权或隐藏
    assert categories == {"org_sop", "responder_experience"}
    rank = {"high": 0, "medium": 1, "low": 2}
    ranks = [rank[item.relevance] for item in knowledge.items]
    assert ranks == sorted(ranks)
    # 每条结果可追溯：来源类别 + knowledge_id@version#chunk_id
    for item in knowledge.items:
        assert item.knowledge_id and item.version and item.chunk_id
        assert item.category_limitations
    # 流程正常完成，未因知识产生校验错误
    assert plan.status in {"recommended", "approval_required"}


def test_single_source_failure_still_presents_remaining_sources(execution):
    adapter = ReferenceKnowledgeAdapter()
    adapter.force_source_status("org_sop", "timeout")
    planner = CapturingPlanner()
    plan = _run(planner, SecurityKnowledgeService(adapter))
    knowledge = planner.seen[0]
    assert knowledge.status == "degraded"
    assert {item.source_category for item in knowledge.items} == {"responder_experience"}
    by_source = {o.source_category: o for o in knowledge.source_outcomes}
    assert by_source["org_sop"].status == "timeout"
    assert any("部分知识来源不可用" in note for note in knowledge.limitations)
    assert plan.status in {"recommended", "approval_required"}


def test_unconfigured_default_keeps_flow_alive(execution):
    planner = CapturingPlanner()
    plan = _run(planner, SecurityKnowledgeService(NullKnowledgeSupplier()))
    knowledge = planner.seen[0]
    assert knowledge.status == "not_configured"
    assert knowledge.items == []
    assert plan.status in {"recommended", "approval_required"}


def test_final_actions_still_cite_knowledge_traceably():
    # 引用格式进得去 ResponseAction 契约；策略校验对处置约束保持原样
    action = ResponseAction(
        action_id="act-1",
        action_type="manual_review",
        target_refs=["host-1"],
        rationale="两份政策对阻断范围描述不一致，需人工确认",
        expected_impact="无系统影响",
        approval_class="none",
        knowledge_refs=["ke-sop-blockip-001@2026.06#c1", "ke-sop-isolate-001@2026.06#c1"],
    )
    assert all("@" in ref and "#" in ref for ref in action.knowledge_refs)


def _conservative_proposal() -> ResponseProposal:
    return ResponseProposal(
        actions=[
            ResponseAction(
                action_id="act-review",
                action_type="manual_review",
                target_refs=["host-1"],
                rationale="复核告警原文与样本",
                judgment_refs=["act-c2-1"],
                preconditions=["安全值班同事可接手"],
                expected_impact="无系统影响，仅占用人工复核时间",
                approval_class="none",
                verification_steps=["复核结论回填到工单"],
            )
        ]
    )


def test_disposal_policy_validation_unchanged_by_knowledge(execution):
    planner = CapturingPlanner()
    plan = _run(planner, SecurityKnowledgeService(ReferenceKnowledgeAdapter()))
    judgment = _judgment()
    # 保守建议照旧通过策略校验：知识接入没有放松处置约束
    assert validate_response_proposal(judgment, _conservative_proposal()) == []
    assert plan.status == "recommended"
    # 空建议照旧被策略拒绝（原有行为不变）
    assert validate_response_proposal(judgment, ResponseProposal())


# -- 生成时的并列呈现规则写进了 planner 提示词 --------------------------------


def test_planner_prompt_carries_full_presentation_rules():
    import inspect

    source = inspect.getsource(StructuredResponsePlanner.__init__)
    for phrase in (
        "Do not drop, downweight or hide any item because",
        "present them side by side",
        "mark the conflict explicitly",
        "require human confirmation",
        "knowledge_id@version#chunk_id",
    ):
        assert phrase in source, phrase
