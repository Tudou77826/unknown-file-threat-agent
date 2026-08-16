from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Protocol

from pydantic import Field

from ...contracts import InvestigationReport, ReportStatement
from ...contracts.investigation import CandidateVerdict
from ...shared import StrictModel
from ...shared.llm import invoke_llm
from ..domain.models import InvestigationState
from .evidence_gate import gate_verdict


PROMPT_VERSION = "investigation-report/1.0"


class ReportDraft(StrictModel):
    verdict: CandidateVerdict
    threat_scenarios: list[str] = Field(default_factory=list)
    executive_summary: str = Field(min_length=1)
    current_situation: list[ReportStatement] = Field(default_factory=list)
    affected_scope: list[ReportStatement] = Field(default_factory=list)
    key_evidence: list[ReportStatement] = Field(default_factory=list)
    supporting_evidence_refs: list[str] = Field(default_factory=list)
    counter_evidence: list[ReportStatement] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    query_boundary_refs: list[str] = Field(default_factory=list)
    asserted_host_refs: list[str] = Field(default_factory=list)
    asserted_start: Any | None = None
    asserted_end: Any | None = None
    confirmed_relation_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


def report_context(state: InvestigationState) -> dict[str, Any]:
    return {
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


class ReportComposer(Protocol):
    def compose(self, state: InvestigationState) -> InvestigationReport: ...
    def validate(self, state: InvestigationState, report: InvestigationReport) -> list[str]: ...
    def repair(self, state: InvestigationState, report: InvestigationReport, errors: list[str]) -> InvestigationReport: ...


class StructuredReportComposer:
    def __init__(self, model: Any, event_sink: Callable | None = None, *, tenant_id: str = "default"):
        self.model_name = str(getattr(model, "model_name", getattr(model, "model", "unknown")))
        self.structured_model = model.with_structured_output(ReportDraft, method="json_mode")
        self.event_sink = event_sink or (lambda _kind, _message, _details=None: None)
        self.tenant_id = tenant_id
        schema = json.dumps(ReportDraft.model_json_schema(), ensure_ascii=False)
        self.system_prompt = (
            "你是未知文件安全调查的主研判模型。基于给定查询接口、实际执行边界、活动与实体关系，"
            "输出结构化简体中文调查报告。不得把查询空结果直接解释为行为未发生，"
            "不得引用输入外对象，不得把 candidate 关系写成已确认关系。最终威胁判断和数据充分性由你负责。"
            "只输出符合下列 ReportDraft JSON Schema 的 JSON 对象，不得增加字段：" + schema
        )

    def compose(self, state: InvestigationState) -> InvestigationReport:
        model_draft = self._generate(json.dumps(report_context(state), ensure_ascii=False))
        model_draft.verdict = gate_verdict(state, model_draft.verdict)
        return self._publish(state, model_draft, version=1)

    def repair(self, state, report, errors):
        return self._sanitize_report(state, report, errors)

    @staticmethod
    @staticmethod
    def _known_refs(state):
        refs = set(state.tool_ledger.authorized_activity_refs)
        for result in state.tool_ledger.query_results:
            refs.update(item.evidence_id for item in result.evidence_references)
            refs.update(item.activity_id for item in result.activities)
        for result in state.tool_ledger.entity_results:
            if result.identity is not None:
                refs.add(result.identity.entity_id)
            refs.update(item.relation_id for item in result.resolved_relations)
            refs.update(item.relation_id for item in result.candidate_relations)
        return refs

    @staticmethod
    def _sanitize_report(state, report, errors):
        """Repair contract references locally; this must not require another LLM call."""
        allowed_refs = StructuredReportComposer._known_refs(state)
        allowed_boundaries = {item.query_id for item in state.tool_ledger.query_results}
        allowed_relations = {
            item.relation_id for result in state.tool_ledger.entity_results
            for item in result.resolved_relations
        }
        repaired = report.model_copy(deep=True)
        repaired.report_version += 1
        repaired.verdict.supporting_refs = [ref for ref in repaired.verdict.supporting_refs if ref in allowed_refs]
        repaired.verdict.contradicting_refs = [ref for ref in repaired.verdict.contradicting_refs if ref in allowed_refs]
        for statement in [*repaired.current_situation, *repaired.affected_scope, *repaired.counter_evidence, *repaired.key_evidence]:
            statement.supporting_refs = [ref for ref in statement.supporting_refs if ref in allowed_refs]
        repaired.supporting_evidence_refs = [ref for ref in repaired.supporting_evidence_refs if ref in allowed_refs]
        repaired.query_boundary_refs = [ref for ref in repaired.query_boundary_refs if ref in allowed_boundaries]
        repaired.asserted_host_refs = [ref for ref in repaired.asserted_host_refs if ref in state.scope.host_ids]
        repaired.confirmed_relation_refs = [ref for ref in repaired.confirmed_relation_refs if ref in allowed_relations]
        if state.scope.start_time and (repaired.asserted_start is None or repaired.asserted_start < state.scope.start_time):
            repaired.asserted_start = state.scope.start_time
        if state.scope.end_time and (repaired.asserted_end is None or repaired.asserted_end > state.scope.end_time):
            repaired.asserted_end = state.scope.end_time
        repaired.limitations.extend(
            f"发布校验已自动修复：{error}" for error in errors
            if f"发布校验已自动修复：{error}" not in repaired.limitations
        )
        return repaired

    def _legacy_model_repair(self, state, report, errors):
        draft = self._generate(json.dumps({
            "task": "只修复引用、Scope、候选关系和结构错误，保持有证据支持的研判语义",
            "validation_errors": errors,
            "previous_report": report.model_dump(mode="json"),
            "context": report_context(state),
        }, ensure_ascii=False))
        return self._publish(state, ReportDraft.model_validate(draft), version=report.report_version + 1)

    def _generate(self, instruction: str) -> ReportDraft:
        # A single large JSON via json_mode; the model can occasionally return
        # malformed/truncated JSON, so the parse is retried with corrective
        # feedback through the shared graded-retry layer.
        messages = [
            {"role": "system", "content": self.system_prompt},
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

    def _publish(self, state, draft, *, version):
        run_id = str(state.raw_input.get("run_id") or "primary")
        digest = hashlib.sha256(f"{state.case_id}:{run_id}:{version}".encode()).hexdigest()[:16]
        return InvestigationReport(
            tenant_id=self.tenant_id,
            case_id=state.case_id,
            source_identity="structured-report-composer",
            report_id=f"report-{digest}", report_version=version, run_id=run_id,
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

    @staticmethod
    def validate(state, report):
        allowed_refs = StructuredReportComposer._known_refs(state)
        candidate_relations = {
            item.relation_id for result in state.tool_ledger.entity_results
            for item in result.candidate_relations
        }
        resolved_relations = {
            item.relation_id for result in state.tool_ledger.entity_results
            for item in result.resolved_relations
        }
        known_boundaries = {item.query_id for item in state.tool_ledger.query_results}
        cited = set(report.supporting_evidence_refs)
        cited |= set(report.verdict.supporting_refs) | set(report.verdict.contradicting_refs)
        for statement in [*report.current_situation, *report.affected_scope, *report.counter_evidence, *report.key_evidence]:
            cited |= set(statement.supporting_refs)
        errors = []
        unknown = sorted(cited - allowed_refs)
        if unknown:
            errors.append(f"报告引用未知对象: {unknown}")
        unknown_boundaries = sorted(set(report.query_boundary_refs) - known_boundaries)
        if unknown_boundaries:
            errors.append(f"报告引用未知查询边界: {unknown_boundaries}")
        outside_hosts = sorted(set(report.asserted_host_refs) - set(state.scope.host_ids))
        if outside_hosts:
            errors.append(f"报告主机超出授权 Scope: {outside_hosts}")
        if report.asserted_start and state.scope.start_time and report.asserted_start < state.scope.start_time:
            errors.append("报告开始时间超出授权 Scope")
        if report.asserted_end and state.scope.end_time and report.asserted_end > state.scope.end_time:
            errors.append("报告结束时间超出授权 Scope")
        candidate_as_confirmed = sorted(set(report.confirmed_relation_refs) & candidate_relations)
        if candidate_as_confirmed:
            errors.append(f"候选关系不能作为确认关系发布: {candidate_as_confirmed}")
        unknown_confirmed = sorted(set(report.confirmed_relation_refs) - resolved_relations)
        if unknown_confirmed:
            errors.append(f"报告确认了未知关系: {unknown_confirmed}")
        return errors
