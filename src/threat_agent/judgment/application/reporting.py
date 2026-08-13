from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Protocol

from pydantic import Field

from ...contracts import InvestigationReport, ReportStatement
from ...contracts.investigation import CandidateVerdict
from ...shared import StrictModel
from ..domain.models import InvestigationState
from ..domain.verdict import evaluate_verdict
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
        "upstream_evidence": [item.model_dump(mode="json") for item in state.evidence],
        "query_results": [item.model_dump(mode="json") for item in state.tool_ledger.query_results],
        "entity_results": [item.model_dump(mode="json") for item in state.tool_ledger.entity_results],
        "metric_results": [item.model_dump(mode="json") for item in state.tool_ledger.metric_results],
        "tool_traces": [item.model_dump(mode="json") for item in state.tool_ledger.traces],
        "active_scenarios": state.active_scenarios,
        "instructions": [
            "returned_count=0 only means this query returned zero rows under its execution boundary",
            "judge data sufficiency yourself; the data layer provides no Coverage grade",
            "candidate entity relations may guide investigation but cannot be stated as confirmed",
            "all material claims must cite a supplied evidence_id or activity_id",
            "authorized_scope.allowed_domains are permissions, not proof that those domains were queried",
            "only query_results represent successful queries; failed tool traces must be stated as limitations",
            "key_evidence is a list of ReportStatement; put each key judgment basis as one statement citing its evidence",
            "write all natural-language content in Simplified Chinese",
        ],
    }


class ReportComposer(Protocol):
    def compose(self, state: InvestigationState) -> InvestigationReport: ...
    def validate(self, state: InvestigationState, report: InvestigationReport) -> list[str]: ...
    def repair(self, state: InvestigationState, report: InvestigationReport, errors: list[str]) -> InvestigationReport: ...


class StructuredReportComposer:
    def __init__(self, model: Any, event_sink: Callable | None = None):
        self.model_name = str(getattr(model, "model_name", getattr(model, "model", "unknown")))
        self.structured_model = model.with_structured_output(ReportDraft, method="json_mode")
        self.event_sink = event_sink or (lambda _kind, _message, _details=None: None)
        schema = json.dumps(ReportDraft.model_json_schema(), ensure_ascii=False)
        self.system_prompt = (
            "你是未知文件安全调查的主研判模型。基于给定查询接口、实际执行边界、活动与实体关系，"
            "输出结构化简体中文调查报告。不得把查询空结果直接解释为行为未发生，"
            "不得引用输入外对象，不得把 candidate 关系写成已确认关系。最终威胁判断和数据充分性由你负责。"
            "只输出符合下列 ReportDraft JSON Schema 的 JSON 对象，不得增加字段：" + schema
        )

    def compose(self, state: InvestigationState) -> InvestigationReport:
        draft = self._generate(json.dumps(report_context(state), ensure_ascii=False))
        model_draft = ReportDraft.model_validate(draft)
        model_draft.verdict = gate_verdict(state, model_draft.verdict)
        return self._publish(state, model_draft, version=1)

    def repair(self, state, report, errors):
        return self._sanitize_report(state, report, errors)

    @staticmethod
    def _sanitize_report(state, report, errors):
        """Repair contract references locally; this must not require another LLM call."""
        known_evidence = {item.evidence_id for item in state.evidence}
        known_evidence |= {
            ref.evidence_id for result in state.tool_ledger.query_results
            for ref in result.evidence_references
        }
        known_evidence |= set(state.tool_ledger.authorized_activity_refs)
        allowed_refs = known_evidence | {item.fact_id for item in state.facts}
        allowed_refs |= {item.finding_id for item in state.findings}
        allowed_refs |= {item.relation_id for item in state.relations}
        allowed_boundaries = {item.query_id for item in state.tool_ledger.query_results}
        allowed_relations = {item.relation_id for item in state.relations}
        allowed_relations |= {
            item.relation_id for result in state.tool_ledger.entity_results
            for item in result.resolved_relations
        }
        repaired = report.model_copy(deep=True)
        repaired.report_version += 1
        repaired.verdict.supporting_refs = [ref for ref in repaired.verdict.supporting_refs if ref in allowed_refs]
        repaired.verdict.contradicting_refs = [ref for ref in repaired.verdict.contradicting_refs if ref in allowed_refs]
        for statement in [*repaired.current_situation, *repaired.affected_scope, *repaired.counter_evidence]:
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

    def _generate(self, instruction: str):
        # Transport retries are owned by the configured chat model. Retrying the
        # whole report call here multiplied a 60-second provider timeout into a
        # several-minute period with no new operational event.
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": instruction},
        ]
        self.event_sink("model_input", "研判报告模型输入", {
            "phase": "judgment_report",
            "messages": messages,
        })
        try:
            output = self.structured_model.invoke(messages)
        except Exception as error:
            self.event_sink("model_output", "研判报告模型调用失败", {
                "phase": "judgment_report",
                "error_type": type(error).__name__,
                "error_message": str(error),
            })
            raise
        self.event_sink("model_output", "研判报告模型输出", {
            "phase": "judgment_report",
            "output": output.model_dump(mode="json") if hasattr(output, "model_dump") else output,
        })
        return output

    def _publish(self, state, draft, *, version):
        run_id = str(state.raw_input.get("run_id") or "primary")
        digest = hashlib.sha256(f"{state.case_id}:{run_id}:{version}".encode()).hexdigest()[:16]
        return InvestigationReport(
            tenant_id=str(state.raw_input.get("tenant_id") or "default"),
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
        known_evidence = {item.evidence_id for item in state.evidence}
        known_evidence |= {
            ref.evidence_id for result in state.tool_ledger.query_results
            for ref in result.evidence_references
        }
        known_evidence |= set(state.tool_ledger.authorized_activity_refs)
        known_facts = {item.fact_id for item in state.facts}
        known_findings = {item.finding_id for item in state.findings}
        known_relations = {item.relation_id for item in state.relations}
        candidate_relations = {
            item.relation_id for result in state.tool_ledger.entity_results
            for item in result.candidate_relations
        }
        resolved_relations = {
            item.relation_id for result in state.tool_ledger.entity_results
            for item in result.resolved_relations
        }
        known_boundaries = {item.query_id for item in state.tool_ledger.query_results}
        allowed_refs = known_evidence | known_facts | known_findings | known_relations
        cited = set(report.supporting_evidence_refs)
        cited |= set(report.verdict.supporting_refs) | set(report.verdict.contradicting_refs)
        for statement in [*report.current_situation, *report.affected_scope, *report.counter_evidence]:
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
        unknown_confirmed = sorted(set(report.confirmed_relation_refs) - resolved_relations - known_relations)
        if unknown_confirmed:
            errors.append(f"报告确认了未知关系: {unknown_confirmed}")
        return errors


class DeterministicReportComposer(StructuredReportComposer):
    """Offline report composer used to verify publication and repair semantics."""

    def __init__(self):
        self.model_name = "deterministic-report-composer/1.0"

    def compose(self, state):
        verdict = state.verdict or evaluate_verdict(state)
        refs = sorted({ref for item in [*state.facts, *state.findings] for ref in item.evidence_refs})
        boundaries = [item.query_id for item in state.tool_ledger.query_results]
        key_evidence = [
            ReportStatement(
                statement_id=item.fact_id,
                text=f"[{item.fact_type}] {item.statement}",
                supporting_refs=list(item.evidence_refs),
            )
            for item in state.facts
        ]
        key_evidence += [
            ReportStatement(
                statement_id=item.finding_id,
                text=f"[{item.finding_type}] {item.statement}（置信度 {int(round(item.confidence * 100))}%）",
                supporting_refs=list(item.evidence_refs),
                limitations=list(item.limitations),
            )
            for item in state.findings
        ]
        draft = ReportDraft(
            verdict=verdict,
            threat_scenarios=list(state.active_scenarios),
            executive_summary=verdict.summary,
            current_situation=[ReportStatement(
                statement_id="situation-1", text=verdict.summary,
                supporting_refs=list(verdict.supporting_refs),
            )],
            key_evidence=key_evidence,
            supporting_evidence_refs=refs,
            unresolved_questions=[item.question for item in state.evidence_gaps if item.status != "resolved"],
            query_boundary_refs=boundaries,
            asserted_host_refs=list(state.scope.host_ids),
            asserted_start=state.scope.start_time,
            asserted_end=state.scope.end_time,
            limitations=list(verdict.limitations),
        )
        return self._publish(state, draft, version=1)

    def repair(self, state, report, errors):
        repaired = self.compose(state)
        repaired.report_version = report.report_version + 1
        return repaired
