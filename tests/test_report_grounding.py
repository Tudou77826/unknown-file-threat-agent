"""Feature 14 — Evidence-Grounded Report Repair acceptance tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from threat_agent.case_management import initialize_state
from threat_agent.contracts import (
    CandidateVerdict,
    JudgmentResult,
    ReportStatement,
    ResponseAction,
    Scope,
    VerdictLevel,
)
from threat_agent.judgment import (
    DeterministicFallbackBuilder,
    JudgmentGraph,
    ReportGroundingValidator,
    ReportPublisher,
    ReportRepairCoordinator,
    StructuredReportComposer,
)
from threat_agent.judgment.application.report_draft import ReportDraft
from threat_agent.judgment.domain.models import FinishRequest
from threat_agent.response_advisory.domain.models import ResponseProposal
from threat_agent.response_advisory.domain.policy import (
    HIGH_RISK_ACTIONS,
    validate_response_proposal,
)


def _state():
    state = initialize_state({
        "File_id": "file-a", "File_hash": "a" * 64, "File_path": "/tmp/a",
        "Sub_asset": "host-1", "tenant_id": "tenant-a", "run_id": "run-a",
    })
    state.scope = Scope(host_ids=["host-1"])
    return state


def _draft(**overrides) -> ReportDraft:
    fields: dict = {
        "verdict": CandidateVerdict(
            level=VerdictLevel.INSUFFICIENT_EVIDENCE, threat_type="unknown",
            summary="当前证据不足以完成定性。",
        ),
        "executive_summary": "当前证据不足以完成定性。",
    }
    fields.update(overrides)
    return ReportDraft(**fields)


# ---------------------------------------------------------------------------
# Publishing invariants (validator floors)
# ---------------------------------------------------------------------------

def test_non_insufficient_verdict_without_support_is_blocking():
    issues = ReportGroundingValidator().validate(
        _state(),
        _draft(verdict=CandidateVerdict(
            level=VerdictLevel.CONFIRMED_MALICIOUS, threat_type="backdoor_c2",
            summary="确认恶意", supporting_refs=[],
        )),
    )
    assert [issue.code for issue in issues] == ["verdict_without_support"]
    assert issues[0].blocking


def test_insufficient_evidence_verdict_without_refs_is_valid():
    assert ReportGroundingValidator().validate(_state(), _draft()) == []


def test_material_statement_without_support_is_blocking():
    issues = ReportGroundingValidator().validate(_state(), _draft(
        current_situation=[ReportStatement(
            statement_id="s1", text="观察到恶意行为", supporting_refs=["unknown-ref"],
        )],
    ))
    codes = {issue.code for issue in issues}
    assert "statement_without_support" in codes


def test_statement_may_cite_executed_query_for_negative_findings():
    from datetime import datetime, timezone

    from threat_agent.contracts import QueryExecutionBoundary, QueryInterfaceDefinition
    from threat_agent.contracts.activity import NetworkActivity
    from threat_agent.contracts.data_boundary import ActivityQueryResult, QueryScopeSnapshot

    now = datetime(2026, 8, 12, tzinfo=timezone.utc)
    activity = NetworkActivity(
        tenant_id="tenant-a", activity_id="act-n1", observed_at=now, ingested_at=now,
        source_system="test", source_record_id="r1", subject_refs=["host:host-1"],
        raw_record_ref="raw-1", normalizer_version="1", host_ref="host-1",
        process_ref="process:host-1:1:1", operation="connect", direction="outbound",
    )
    scope = QueryScopeSnapshot(host_refs=["host-1"])
    boundary = QueryExecutionBoundary(
        interface_id="activity-query/network", interface_version="1",
        requested_scope=scope, applied_scope=scope,
        returned_count=1, page_limit=10, executed_at=now,
    )
    interface = QueryInterfaceDefinition(
        tenant_id="tenant-a", interface_id="activity-query/network", interface_version="1",
        activity_types=["network"],
        fields=[{"name": "activity_id", "value_type": "string", "semantic": "id", "nullable": False}],
        max_page_size=1000,
    )
    state = _state()
    state.tool_ledger.query_results.append(ActivityQueryResult(
        tenant_id="tenant-a", case_id="case-a", source_identity="test", run_id="run-a",
        query_id="q-network-1", interface_definition=interface,
        execution_boundary=boundary, activities=[activity], evidence_references=[],
    ))
    draft = _draft(
        current_situation=[ReportStatement(
            statement_id="s1", text="在查询边界内未观察到外联行为",
            supporting_refs=["q-network-1"],
        )],
    )
    assert ReportGroundingValidator().validate(state, draft) == []


def test_out_of_scope_clue_refs_are_known_but_uncitable():
    from threat_agent.contracts import EntityExplorationResult, OutOfScopeRelationClue
    state = _state()
    state.tool_ledger.entity_results.append(EntityExplorationResult(
        out_of_scope_relations=[OutOfScopeRelationClue(
            relation_id="relation-x", other_endpoint_ref="process:host-2:1:1",
        )],
        returned_count=0,
    ))
    issues = ReportGroundingValidator().validate(state, _draft(
        supporting_evidence_refs=["relation-x"],
    ))
    assert issues and issues[0].code == "evidence_ref_out_of_scope"


def test_time_and_host_assertions_and_query_boundaries_are_located():
    from datetime import datetime, timezone
    state = _state()
    state.scope = Scope(
        host_ids=["host-1"],
        start_time=datetime(2026, 4, 23, tzinfo=timezone.utc),
        end_time=datetime(2026, 4, 24, tzinfo=timezone.utc),
    )
    issues = ReportGroundingValidator().validate(state, _draft(
        asserted_host_refs=["host-2"],
        asserted_start=datetime(2026, 4, 22, tzinfo=timezone.utc),
        asserted_end=datetime(2026, 4, 25, tzinfo=timezone.utc),
        query_boundary_refs=["never-executed"],
    ))
    codes = {(issue.code, issue.location) for issue in issues}
    assert ("host_assertion_out_of_scope", "asserted_host_refs") in codes
    assert ("time_assertion_out_of_scope", "asserted_start") in codes
    assert ("time_assertion_out_of_scope", "asserted_end") in codes
    assert ("query_boundary_not_executed", "query_boundary_refs") in codes
    assert all(issue.blocking for issue in issues)


# ---------------------------------------------------------------------------
# Coordinator: budget, rejudgment, unified failure path
# ---------------------------------------------------------------------------

class _ScriptedComposer:
    model_name = "fake-model"

    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.compose_calls = 0
        self.rejudge_calls = 0

    def compose_draft(self, _state):
        self.compose_calls += 1
        return self._next()

    def rejudge(self, _state, _previous, _issues, *, attempt):
        self.rejudge_calls += 1
        return self._next()

    def _next(self):
        item = self.outputs.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_clean_draft_passes_without_extra_model_calls():
    composer = _ScriptedComposer([_draft()])
    outcome = ReportRepairCoordinator(composer).evaluate(
        _state(), _draft(), max_rejudgments=2
    )
    assert outcome.issues == []
    assert outcome.rejudgments_used == 0
    assert composer.rejudge_calls == 0


def test_budget_exhaustion_keeps_issues_and_marks_exhausted():
    composer = _ScriptedComposer([])  # no rejudge budget spent -> no model call
    broken = _draft(verdict=CandidateVerdict(
        level=VerdictLevel.SUSPICIOUS, threat_type="unknown",
        summary="引用未知证据", supporting_refs=["ghost-ref"],
    ))
    outcome = ReportRepairCoordinator(composer).evaluate(
        _state(), broken, max_rejudgments=0
    )
    assert outcome.exhausted
    assert outcome.rejudgments_used == 0
    assert {issue.code for issue in outcome.issues} == {"unknown_evidence_ref"}


def test_model_failure_consumes_budget_and_funnels_to_fallback():
    events = []
    composer = _ScriptedComposer([TimeoutError("model timeout")])
    broken = _draft(supporting_evidence_refs=["ghost-ref"])
    outcome = ReportRepairCoordinator(
        composer, event_sink=lambda kind, message, details=None: events.append(
            (kind, message, details)
        ),
    ).evaluate(_state(), broken, max_rejudgments=2)
    assert outcome.exhausted
    assert outcome.rejudgments_used == 1
    repair_events = [item for item in events if item[0] == "repair"]
    assert repair_events and "失败" in repair_events[0][1]
    assert repair_events[0][2]["error_type"] == "TimeoutError"
    assert repair_events[0][2]["issue_codes"] == ["unknown_evidence_ref"]


def test_events_carry_attempt_codes_and_locations():
    events = []
    composer = _ScriptedComposer([_draft()])
    broken = _draft(current_situation=[ReportStatement(
        statement_id="s1", text="无引用陈述", supporting_refs=[],
    )])
    ReportRepairCoordinator(
        composer, event_sink=lambda kind, message, details=None: events.append(
            (kind, message, details)
        ),
    ).evaluate(_state(), broken, max_rejudgments=2)
    validations = [item for item in events if item[0] == "validation"]
    assert validations[0][2]["attempt"] == 0
    assert "statement_without_support" in validations[0][2]["issue_codes"]
    assert "current_situation[s1].supporting_refs" in validations[0][2]["issue_locations"]
    repairs = [item for item in events if item[0] == "repair"]
    assert repairs[0][2]["attempt"] == 1
    assert repairs[0][2]["previous_issue_codes"] == ["statement_without_support"]


# ---------------------------------------------------------------------------
# Fallback builder and publisher
# ---------------------------------------------------------------------------

def test_fallback_builder_carries_no_safety_assertions():
    state = _state()
    issues = ReportGroundingValidator().validate(_state(), _draft(
        verdict=CandidateVerdict(
            level=VerdictLevel.CONFIRMED_MALICIOUS, threat_type="backdoor_c2",
            summary="确认恶意", supporting_refs=[],
        ),
        threat_scenarios=["C2 回连"],
        executive_summary="确认恶意的摘要。",
    ))
    assert {issue.code for issue in issues} == {"verdict_without_support"}
    draft = DeterministicFallbackBuilder().build_draft(state, issues)
    assert draft.verdict.level == VerdictLevel.INSUFFICIENT_EVIDENCE
    assert draft.verdict.threat_type == "unknown"
    assert draft.verdict.supporting_refs == []
    assert draft.threat_scenarios == []
    assert draft.key_evidence == [] and draft.current_situation == []
    assert "report_grounding_failed" in draft.limitations
    assert any("verdict_without_support" in item for item in draft.limitations)
    assert draft.unresolved_questions
    assert draft.asserted_host_refs == ["host-1"]


def test_publisher_is_the_only_report_constructor_and_mints_versions_once():
    state = _state()
    report = ReportPublisher(tenant_id="demo", run_id="run-1", model_name="m").publish(
        state, _draft(), publication_status="grounded"
    )
    assert report.publication_status == "grounded"
    assert report.report_version == 1
    fallback = ReportPublisher(tenant_id="demo", run_id="run-1", model_name="m").publish(
        state, DeterministicFallbackBuilder().build_draft(state, []), publication_status="fallback",
    )
    assert fallback.publication_status == "fallback"
    with pytest.raises(ValueError):
        ReportPublisher().publish(state, _draft(), publication_status="draft")


# ---------------------------------------------------------------------------
# Graph-level publication flow
# ---------------------------------------------------------------------------

class _FinishPlanner:
    uses_data_tools = True

    def plan(self, _state):
        return [FinishRequest(objective="证据已经足够，结束调查并生成报告")]


def _graph(composer, **kwargs):
    return JudgmentGraph(
        _FinishPlanner(),
        tenant_id="demo",
        run_id="run-1",
        report_composer=composer,
        **kwargs,
    )


def test_graph_publishes_grounded_report_on_first_pass():
    composer = _ScriptedComposer([_draft()])
    result = _graph(composer).run(_state())
    report = result.investigation_report
    assert report is not None and report.publication_status == "grounded"
    assert composer.rejudge_calls == 0
    assert result.report_validation_errors == []
    assert result.verdict.level == VerdictLevel.INSUFFICIENT_EVIDENCE


def test_graph_rejudges_then_publishes_grounded():
    broken = _draft(verdict=CandidateVerdict(
        level=VerdictLevel.SUSPICIOUS, threat_type="unknown",
        summary="引用未知证据的可疑结论", supporting_refs=["ghost-ref"],
    ))
    composer = _ScriptedComposer([broken, _draft()])
    result = _graph(composer).run(_state())
    assert composer.rejudge_calls == 1
    assert result.investigation_report.publication_status == "grounded"
    assert result.budget.report_rejudgments_used == 1


def test_graph_publishes_fallback_when_rejudgment_exhausted():
    broken = _draft(verdict=CandidateVerdict(
        level=VerdictLevel.SUSPICIOUS, threat_type="unknown",
        summary="始终引用未知证据", supporting_refs=["ghost-ref"],
    ))
    state = _state()
    state.budget.max_report_rejudgments = 1
    composer = _ScriptedComposer([broken, broken])
    result = _graph(composer).run(state)
    report = result.investigation_report
    assert report.publication_status == "fallback"
    assert report.verdict.level == VerdictLevel.INSUFFICIENT_EVIDENCE
    assert report.threat_scenarios == [] and report.key_evidence == []
    assert "report_grounding_failed" in report.limitations
    # The failed draft's safety conclusion must not survive.
    assert "可疑" not in report.executive_summary
    assert result.report_validation_errors
    assert result.verdict.level == VerdictLevel.INSUFFICIENT_EVIDENCE


# ---------------------------------------------------------------------------
# Response advisory: fallback cannot justify high-impact actions
# ---------------------------------------------------------------------------

def _judgment(publication_status="grounded"):
    return JudgmentResult(
        tenant_id="demo", case_id="case-a", source_identity="test",
        verdict=CandidateVerdict(
            level=VerdictLevel.INSUFFICIENT_EVIDENCE, threat_type="unknown",
            summary="证据不足",
        ),
        evidence_refs=["activity-1"],
        publication_status=publication_status,
    )


def _proposal(action_type="collect_more_data", approval_class="none"):
    return ResponseProposal(actions=[ResponseAction(
        action_id="a1", action_type=action_type, rationale="理由",
        judgment_refs=["activity-1"], preconditions=["前提"],
        expected_impact="低", approval_class=approval_class,
        rollback_steps=["回滚"], verification_steps=["验证"],
    )])


def test_fallback_judgment_rejects_high_impact_actions():
    errors = validate_response_proposal(_judgment("fallback"), _proposal("isolate_host", "security_lead"))
    assert any("Fallback publication cannot justify" in item for item in errors)


def test_grounded_judgment_allows_approved_high_impact_actions():
    action_type = sorted(HIGH_RISK_ACTIONS)[0]
    errors = validate_response_proposal(_judgment("grounded"), _proposal(action_type, "security_lead"))
    assert not any("Fallback publication" in item for item in errors)


def test_fallback_judgment_allows_low_impact_review_actions():
    assert validate_response_proposal(_judgment("fallback"), _proposal()) == []
