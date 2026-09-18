from __future__ import annotations

import hashlib
import json
from typing import Any, Callable

from ...contracts import InvestigationReport
from ...contracts.investigation import CandidateVerdict, VerdictLevel
from ...shared.llm import invoke_llm, structured_output_method
from ..domain.models import InvestigationState
from .report_draft import ReportDraft
from .report_validation import (
    ReportValidationIssue,
    executed_query_ids,
)

PROMPT_VERSION = "investigation-report/1.1"


def report_context(state: InvestigationState) -> dict[str, Any]:
    context: dict[str, Any] = {
        "case_id": state.case_id,
        "authorized_scope": state.scope.model_dump(mode="json"),
        "entities": [item.model_dump(mode="json") for item in state.entities],
        "query_results": [item.model_dump(mode="json") for item in state.tool_ledger.query_results],
        "entity_results": [item.model_dump(mode="json") for item in state.tool_ledger.entity_results],
        "metric_results": [item.model_dump(mode="json") for item in state.tool_ledger.metric_results],
        "tool_traces": [item.model_dump(mode="json") for item in state.tool_ledger.traces],
        "instructions": [
            "returned_count=0 only means this query returned zero rows under its execution boundary",
            "judge data sufficiency yourself; the data layer provides no Coverage grade",
            "candidate entity relations may guide investigation but cannot be stated as confirmed",
            "all material claims must cite a supplied evidence_id or activity_id",
            "authorized_scope.allowed_domains are permissions, not proof that those domains were queried",
            "only query_results represent successful queries; failed tool traces must be stated as limitations",
            "cross-host leads are out of investigation scope: record them only as unresolved_questions or limitations, never as confirmed facts about target hosts",
            "key_evidence is a list of ReportStatement; put each key judgment basis as one statement citing its evidence",
            "write all natural-language content in Simplified Chinese",
        ],
    }
    if state.knowledge_guidance:
        # 基线检索合并后的调查指引：内容连同来源类别与适用限制一起给出，
        # 但知识条目不是案件证据——引用约束由 instructions 与接地校验双重保证。
        context["knowledge_guidance"] = [
            item.model_dump(mode="json") for item in state.knowledge_guidance
        ]
        context["instructions"].append(
            "knowledge_guidance is external reference only: it may guide wording, "
            "hypotheses and next-step suggestions, but must never be cited as "
            "supporting_evidence_refs or stated as a fact about this case"
        )
    return context


def evidence_catalog(state: InvestigationState) -> dict[str, Any]:
    """Whitelist of citable evidence for constrained rejudgment.

    Identifiers and minimal deterministic summaries only: out-of-scope object
    content never enters the rejudgment context.
    """

    activities = []
    for result in state.tool_ledger.query_results:
        for activity in result.activities:
            activities.append({
                "activity_id": activity.activity_id,
                "type": activity.activity_type,
                "observed_at": activity.observed_at.isoformat(),
                "operation": getattr(activity, "operation", None),
                "subject_refs": list(activity.subject_refs),
            })
    evidence_ids = [
        item.evidence_id
        for result in state.tool_ledger.query_results
        for item in result.evidence_references
    ]
    relations = [
        item.relation_id
        for result in state.tool_ledger.entity_results
        for item in result.resolved_relations
    ]
    return {
        "citable_activity_ids": sorted(state.tool_ledger.authorized_activity_refs),
        "citable_evidence_ids": sorted(evidence_ids),
        "citable_relation_ids": sorted(relations),
        "activity_summaries": activities,
        "executed_query_ids": sorted(executed_query_ids(state)),
    }


class StructuredReportComposer:
    """LLM draft generation and constrained rejudgment; never publishes."""

    def __init__(self, model: Any, event_sink: Callable | None = None, *, tenant_id: str = "default"):
        self.model_name = str(getattr(model, "model_name", getattr(model, "model", "unknown")))
        self.structured_model = model.with_structured_output(
            ReportDraft, method=structured_output_method(model)
        )
        self.event_sink = event_sink or (lambda _kind, _message, _details=None: None)
        self.tenant_id = tenant_id
        schema = json.dumps(ReportDraft.model_json_schema(), ensure_ascii=False)
        self.system_prompt = (
            "你是未知文件安全调查的主研判模型。基于给定查询接口、实际执行边界、活动与实体关系，"
            "输出结构化简体中文调查报告。不得把查询空结果直接解释为行为未发生，"
            "不得引用输入外对象，不得把 candidate 关系写成已确认关系。最终威胁判断和数据充分性由你负责。"
            "只输出符合下列 ReportDraft JSON Schema 的 JSON 对象，不得增加字段：" + schema
        )
        self.rejudge_system_prompt = (
            "你是未知文件安全调查的重新研判模型。上一版报告草稿未通过发布校验，"
            "你将收到结构化校验问题、当前授权 Scope 和本次运行合法证据的白名单。"
            "规则：只能引用白名单中的 ID，不得构造或模糊匹配引用；"
            "引用、事实陈述和结论是一个语义整体，任一单元包含非法引用时必须重写或删除整个单元"
            "（Verdict 单元＝verdict/executive_summary/threat_scenarios/key_evidence 及报告级引用；"
            "Statement 单元＝陈述文本/支撑引用/限制；Scope 单元＝受影响范围/主机与时间断言/确认关系）；"
            "你被明确允许修改、降低或完全放弃原有结论，包括改为证据不足；不得被要求保持原结论。"
            "只输出符合 ReportDraft JSON Schema 的完整 JSON 对象：" + schema
        )

    def compose_draft(self, state: InvestigationState) -> ReportDraft:
        return self._generate(
            self.system_prompt, json.dumps(report_context(state), ensure_ascii=False)
        )

    def rejudge(
        self,
        state: InvestigationState,
        previous_draft: ReportDraft,
        issues: list[ReportValidationIssue],
        *,
        attempt: int,
    ) -> ReportDraft:
        instruction = json.dumps({
            "task": "根据校验问题重新研判并输出完整的新 ReportDraft",
            "attempt": attempt,
            "previous_draft": previous_draft.model_dump(mode="json"),
            "validation_issues": [
                {
                    "code": issue.code,
                    "location": issue.location,
                    "invalid_refs": issue.invalid_refs,
                }
                for issue in issues
            ],
            "authorized_scope": state.scope.model_dump(mode="json"),
            "authorized_evidence": evidence_catalog(state),
            "constraint": "只可引用 authorized_evidence 白名单中的 ID；允许改变结论",
        }, ensure_ascii=False)
        return self._generate(self.rejudge_system_prompt, instruction)

    def _generate(self, system_prompt: str, instruction: str) -> ReportDraft:
        # A single large JSON via json_mode; the model can occasionally return
        # malformed/truncated JSON, so the parse is retried with corrective
        # feedback through the shared graded-retry layer.
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": instruction},
        ]

        def invoke_once() -> ReportDraft:
            return ReportDraft.model_validate(self.structured_model.invoke(messages))

        def build_feedback(_attempt: int, error: Exception):
            return {
                "role": "user",
                "content": (
                    "The previous output was not valid ReportDraft JSON. Return only a "
                    "complete JSON object matching the schema, without truncation or "
                    f"extra fields. Parse error: {str(error)[:800]}"
                ),
            }

        def on_attempt(attempt: int) -> None:
            self.event_sink("model_input", "研判报告模型输入", {
                "phase": "judgment_report",
                "attempt": attempt,
                "messages": messages,
            })

        def on_output(_attempt: int, output: ReportDraft) -> None:
            self.event_sink("model_output", "研判报告模型输出", {
                "phase": "judgment_report",
                "output": output.model_dump(mode="json"),
            })

        def on_failure(attempt: int, error: Exception, kind: str) -> None:
            self.event_sink(
                "model_output",
                "研判报告模型输出校验失败" if kind == "parse" else "研判报告模型调用失败",
                {
                    "phase": "judgment_report",
                    "attempt": attempt,
                    "error_type": type(error).__name__,
                    "error_message": str(error),
                },
            )

        return invoke_llm(
            invoke_once,
            messages=messages,
            build_feedback=build_feedback,
            on_attempt=on_attempt,
            on_output=on_output,
            on_failure=on_failure,
            parse_max_attempts=3,
        )


class ReportPublisher:
    """The only component allowed to construct a formal InvestigationReport."""

    def __init__(self, *, tenant_id: str = "default", run_id: str = "primary", model_name: str = "unknown"):
        self.tenant_id = tenant_id
        self.run_id = run_id
        self.model_name = model_name

    def publish(
        self,
        state: InvestigationState,
        draft: ReportDraft,
        *,
        publication_status: str,
    ) -> InvestigationReport:
        if publication_status not in {"grounded", "fallback"}:
            raise ValueError(f"Unknown publication status: {publication_status}")
        run_id = self.run_id
        # Report versions are minted only at publication; model rejudgment
        # attempts are run events, not report versions.
        digest = hashlib.sha256(f"{state.case_id}:{run_id}:{publication_status}".encode()).hexdigest()[:16]
        return InvestigationReport(
            tenant_id=self.tenant_id,
            case_id=state.case_id,
            source_identity="structured-report-composer",
            report_id=f"report-{digest}", report_version=1, run_id=run_id,
            publication_status=publication_status,
            verdict=draft.verdict, threat_scenarios=draft.threat_scenarios,
            executive_summary=draft.executive_summary,
            current_situation=draft.current_situation, affected_scope=draft.affected_scope,
            key_evidence=draft.key_evidence,
            supporting_evidence_refs=draft.supporting_evidence_refs,
            counter_evidence=draft.counter_evidence,
            unresolved_questions=draft.unresolved_questions,
            query_boundary_refs=draft.query_boundary_refs,
            asserted_host_refs=draft.asserted_host_refs,
            asserted_start=draft.asserted_start, asserted_end=draft.asserted_end,
            confirmed_relation_refs=draft.confirmed_relation_refs,
            limitations=draft.limitations,
            producer="judgment-report-graph", model_version=self.model_name,
            prompt_version=PROMPT_VERSION,
        )


class DeterministicFallbackBuilder:
    """Build the machine-recognizable insufficient-evidence fallback draft.

    Carries no safety assertions from the failed draft: no verdict, summary,
    scenarios, statements or relations are copied.
    """

    FALLBACK_SUMMARY = (
        "本次调查未能发布可追溯的正式研判报告：报告引用与结论的接地校验未在预算内通过。"
        "系统不保留任何原结论或事实断言，当前唯一可信状态是证据不足。"
        "请重新生成报告或补充调查后重新研判。"
    )

    def build_draft(
        self, state: InvestigationState, issues: list[ReportValidationIssue]
    ) -> ReportDraft:
        codes = sorted({issue.code for issue in issues})
        draft = ReportDraft(
            verdict=CandidateVerdict(
                level=VerdictLevel.INSUFFICIENT_EVIDENCE,
                threat_type="unknown",
                summary=self.FALLBACK_SUMMARY,
                supporting_refs=[],
                contradicting_refs=[],
                limitations=["report_grounding_failed"],
            ),
            threat_scenarios=[],
            executive_summary=self.FALLBACK_SUMMARY,
            current_situation=[],
            affected_scope=[],
            key_evidence=[],
            supporting_evidence_refs=[],
            counter_evidence=[],
            unresolved_questions=[
                "报告接地校验未通过，需要重新生成报告或补充调查数据后重新研判",
            ],
            query_boundary_refs=sorted(executed_query_ids(state)),
            asserted_host_refs=list(state.scope.host_ids),
            asserted_start=state.scope.start_time,
            asserted_end=state.scope.end_time,
            confirmed_relation_refs=[],
            limitations=[
                "report_grounding_failed",
                *(f"validation_issue:{code}" for code in codes),
            ],
        )
        self.validate_fallback(draft, state)
        return draft

    @staticmethod
    def validate_fallback(draft: ReportDraft, state: InvestigationState) -> None:
        """Deterministic fallback invariants; violation is a programming error."""

        assert draft.verdict.level == VerdictLevel.INSUFFICIENT_EVIDENCE, (
            "fallback verdict must be insufficient_evidence"
        )
        assert draft.verdict.threat_type == "unknown"
        assert not draft.verdict.supporting_refs and not draft.verdict.contradicting_refs
        assert not draft.threat_scenarios
        assert not draft.current_situation and not draft.affected_scope
        assert not draft.key_evidence and not draft.counter_evidence
        assert not draft.supporting_evidence_refs and not draft.confirmed_relation_refs
        assert set(draft.query_boundary_refs) <= executed_query_ids(state)
        assert set(draft.asserted_host_refs) <= set(state.scope.host_ids)
        assert "report_grounding_failed" in draft.limitations
