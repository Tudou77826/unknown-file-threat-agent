"""Assembled report pipeline unit tests.

Covers the three contracts of ``report_assembly``:

- pointer resolution (short pointer, canonical ID, unknown rejected);
- deterministic assembly of every mechanical field from the ledger;
- tiered repair (deterministic backstops, minimal-edit re-judgment loop,
  degradation to the legacy path on judgment-call failure).
"""

from __future__ import annotations

from datetime import datetime, timezone

from threat_agent.contracts.activity import ProcessActivity
from threat_agent.contracts.data_boundary import (
    ActivityQueryResult,
    EvidenceReference,
    QueryExecutionBoundary,
    QueryFieldDefinition,
    QueryInterfaceDefinition,
    QueryScopeSnapshot,
)
from threat_agent.contracts.evidence import Scope
from threat_agent.contracts.investigation import CandidateVerdict
from threat_agent.contracts.investigation_tools import (
    EntityExplorationResult,
    InvestigationToolLedger,
    ObservedRelation,
)
from threat_agent.judgment.application.graph import publish_investigation_report
from threat_agent.judgment.application.report_assembly import (
    AssembledReportComposer,
    InvestigationJudgment,
    JudgmentUnit,
    PointerCatalog,
    apply_assembly_backstops,
    assemble_report_draft,
    publish_report_via_assembly,
)
from threat_agent.judgment.application.report_draft import ReportDraft
from threat_agent.judgment.application.report_validation import (
    ReportGroundingValidator,
    ReportValidationIssue,
)
from threat_agent.judgment.domain.models import InvestigationState

UTC = timezone.utc


def _activity(activity_id: str, observed_at: datetime, *, host: str = "host-1") -> ProcessActivity:
    return ProcessActivity(
        tenant_id="default",
        activity_id=activity_id,
        observed_at=observed_at,
        ingested_at=observed_at,
        source_system="auditd",
        source_record_id=f"rec-{activity_id}",
        subject_refs=[f"process:{host}:4242:{observed_at.isoformat()}"],
        raw_record_ref=f"raw-{activity_id}",
        normalizer_version="v1",
        host_ref=host,
        process_ref=f"process:{host}:4242:{observed_at.isoformat()}",
        pid=4242,
        operation="execute",
        executable="/tmp/.cache/sysupd",
    )


def _query_result(
    query_id: str, activities: list[ProcessActivity]
) -> ActivityQueryResult:
    interface = QueryInterfaceDefinition(
        tenant_id="default",
        interface_id="query_process_activities",
        interface_version="1",
        activity_types=["process"],
        fields=[QueryFieldDefinition(name="executable", value_type="string", semantic="path")],
        max_page_size=200,
    )
    boundary = QueryExecutionBoundary(
        interface_id=interface.interface_id,
        interface_version=interface.interface_version,
        requested_scope=QueryScopeSnapshot(),
        applied_scope=QueryScopeSnapshot(host_refs=["host-1"]),
        returned_count=len(activities),
        page_limit=200,
        executed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    return ActivityQueryResult(
        tenant_id="default",
        case_id="case-1",
        run_id="run-1",
        query_id=query_id,
        interface_definition=interface,
        execution_boundary=boundary,
        activities=activities,
        evidence_references=[
            EvidenceReference(
                tenant_id="default",
                case_id="case-1",
                run_id="run-1",
                evidence_id=f"ev-{activity.activity_id}",
                query_id=query_id,
                activity_ref=activity.activity_id,
            )
            for activity in activities
        ],
    )


def _state() -> InvestigationState:
    activities = [
        _activity("activity-raw-001", datetime(2026, 1, 1, 12, 0, tzinfo=UTC)),
        _activity("activity-raw-002", datetime(2026, 1, 1, 12, 5, tzinfo=UTC)),
    ]
    query = _query_result("query-001", activities)
    resolved = ObservedRelation(
        tenant_id="default",
        relation_id="rel-resolved-1",
        relation_type="process_file",
        source_entity_ref="process:host-1:4242",
        target_entity_ref="file:/tmp/.cache/sysupd",
        supporting_activity_refs=["activity-raw-001"],
        resolution_status="resolved",
        confidence=1.0,
        resolver_version="v1",
    )
    candidate = ObservedRelation(
        tenant_id="default",
        relation_id="rel-candidate-1",
        relation_type="process_file",
        source_entity_ref="process:host-1:4242",
        target_entity_ref="file:/etc/passwd",
        resolution_status="candidate",
        confidence=0.4,
        ambiguity_reason="single observation",
        resolver_version="v1",
    )
    state = InvestigationState(
        case_id="case-1",
        raw_input={"File_path": "/tmp/.cache/sysupd"},
        entities=[],
        scope=Scope(
            host_ids=["host-1"],
            start_time=datetime(2026, 1, 1, 0, 0, tzinfo=UTC),
            end_time=datetime(2026, 1, 1, 23, 0, tzinfo=UTC),
        ),
    )
    state.tool_ledger = InvestigationToolLedger(
        query_results=[query],
        entity_results=[
            EntityExplorationResult(
                resolved_relations=[resolved],
                candidate_relations=[candidate],
                returned_count=0,
            )
        ],
        authorized_activity_refs=["activity-raw-001", "activity-raw-002"],
    )
    return state


def _judgment(**overrides) -> InvestigationJudgment:
    base = dict(
        verdict_level="confirmed_malicious",
        threat_type="backdoor_c2",
        verdict_summary="样本为持久化后门并周期性回连。",
        threat_scenarios=["webshell_persistence"],
        verdict_refs=["a001", "a002"],
        contradicting_refs=[],
        units=[
            JudgmentUnit(section="key_evidence", text="样本以隐藏路径落地并被执行。", refs=["a001"]),
            JudgmentUnit(section="current_situation", text="进程持续驻留。", refs=["a002"]),
        ],
        confirmed_relations=["r001"],
        unresolved_questions=["回连目标归属未确认。"],
        limitations=[],
    )
    base.update(overrides)
    return InvestigationJudgment(**base)


# -- pointer catalog -----------------------------------------------------------


def test_pointer_catalog_resolves_pointer_canonical_and_rejects_unknown():
    catalog = PointerCatalog.build(_state())
    resolved, rejected = catalog.resolve(["a001", "activity-raw-002", "A001", "ev-activity-raw-001", "nope"])
    assert resolved == ["activity-raw-001", "activity-raw-002", "ev-activity-raw-001"]
    assert rejected == ["nope"]


def test_pointer_catalog_index_lists_all_pointer_kinds():
    catalog = PointerCatalog.build(_state())
    index = catalog.index()
    assert {entry["ptr"] for entry in index["activities"]} == {"a001", "a002"}
    assert {entry["ptr"] for entry in index["evidence"]} == {"e001", "e002"}
    assert {entry["ptr"] for entry in index["relations_resolved"]} == {"r001"}
    assert {entry["ptr"] for entry in index["relations_candidate"]} == {"c001"}
    assert {entry["ptr"] for entry in index["queries"]} == {"q001"}
    activity_entry = index["activities"][0]
    assert activity_entry["activity_id"] == "activity-raw-001"
    assert activity_entry["host"] == "host-1"
    assert activity_entry["type"] == "process"


# -- deterministic assembly ----------------------------------------------------


def test_assembly_fills_mechanical_fields_from_ledger():
    state = _state()
    catalog = PointerCatalog.build(state)
    draft, notes = assemble_report_draft(state, _judgment(), catalog)

    assert draft.query_boundary_refs == ["query-001"]  # executed queries, ledger truth
    assert draft.asserted_host_refs == ["host-1"]  # hosts of cited activities
    assert draft.asserted_start == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    assert draft.asserted_end == datetime(2026, 1, 1, 12, 5, tzinfo=UTC)
    assert draft.key_evidence[0].statement_id == "ke-01"
    assert draft.current_situation[0].statement_id == "cs-01"
    assert draft.key_evidence[0].supporting_refs == ["activity-raw-001"]
    assert draft.verdict.supporting_refs == ["activity-raw-001", "activity-raw-002"]
    # Supporting union = verdict refs + non-counter statement refs.
    assert draft.supporting_evidence_refs == ["activity-raw-001", "activity-raw-002"]
    assert draft.confirmed_relation_refs == ["rel-resolved-1"]
    assert notes.dropped_refs == []
    assert notes.downgraded_relations == []
    assert ReportGroundingValidator().validate(state, draft) == []


def test_assembly_downgrades_candidate_relations_and_drops_unknown_refs():
    state = _state()
    catalog = PointerCatalog.build(state)
    judgment = _judgment(
        confirmed_relations=["r001", "c001"],
        verdict_refs=["a001", "made-up-ref"],
        units=[
            JudgmentUnit(section="key_evidence", text="陈述", refs=["a001", "ghost"]),
        ],
    )
    draft, notes = assemble_report_draft(state, judgment, catalog)

    assert draft.confirmed_relation_refs == ["rel-resolved-1"]
    assert notes.downgraded_relations == ["rel-candidate-1"]
    assert "candidate_relation_not_confirmed:rel-candidate-1" in draft.limitations
    assert set(notes.dropped_refs) == {"made-up-ref", "ghost"}
    assert draft.key_evidence[0].supporting_refs == ["activity-raw-001"]
    assert "dropped_refs:ghost" in draft.key_evidence[0].limitations


def test_assembly_clamps_times_to_scope_and_defaults_hosts():
    state = _state()
    catalog = PointerCatalog.build(state)
    judgment = _judgment(verdict_refs=[], units=[])
    draft, _ = assemble_report_draft(state, judgment, catalog)

    # No cited activities: scope hosts and scope window are the assertion.
    assert draft.asserted_host_refs == ["host-1"]
    assert draft.asserted_start == state.scope.start_time
    assert draft.asserted_end == state.scope.end_time


# -- tier-1 backstops ----------------------------------------------------------


def test_backstops_fix_mechanical_violations_without_llm():
    state = _state()
    draft = ReportDraft(
        verdict=CandidateVerdict(
            level="confirmed_malicious",
            threat_type="backdoor_c2",
            summary="x",
            supporting_refs=["activity-raw-001"],
        ),
        executive_summary="x",
        query_boundary_refs=["query-ghost"],
        asserted_host_refs=["host-9"],
        asserted_start=datetime(2025, 12, 1, tzinfo=UTC),
        asserted_end=datetime(2026, 3, 1, tzinfo=UTC),
        confirmed_relation_refs=["rel-candidate-1"],
        supporting_evidence_refs=["activity-raw-001", "unknown-ref"],
    )
    issues = ReportGroundingValidator().validate(state, draft)
    codes = {issue.code for issue in issues}
    assert {
        "query_boundary_not_executed",
        "host_assertion_out_of_scope",
        "time_assertion_out_of_scope",
        "relation_not_confirmed",
    } <= codes

    fixed, changed = apply_assembly_backstops(state, draft, issues)
    assert changed
    assert fixed.query_boundary_refs == ["query-001"]
    assert fixed.asserted_host_refs == ["host-1"]
    assert fixed.asserted_start == state.scope.start_time
    assert fixed.asserted_end == state.scope.end_time
    assert fixed.confirmed_relation_refs == []
    assert "unknown-ref" not in fixed.supporting_evidence_refs
    assert ReportGroundingValidator().validate(state, fixed) == []


# -- pipeline flow -------------------------------------------------------------


class _FakeAssembledComposer:
    """Composer double implementing the assembled-pipeline contract."""

    pipeline = "assembled"
    model_name = "fake-assembled"
    event_sink = staticmethod(lambda *_a, **_k: None)

    def __init__(self, judgments):
        self.judgments = list(judgments)
        self.synthesis_inputs: list = []
        self.rejudge_inputs: list = []

    def synthesize(self, state, catalog):
        self.synthesis_inputs.append(catalog)
        item = self.judgments.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def rejudge_judgment(self, state, judgment, catalog, issues, *, attempt):
        self.rejudge_inputs.append((judgment, issues))
        item = self.judgments.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    # legacy passthrough (degradation path) — should never be reached in tests
    def compose_draft(self, state):
        raise AssertionError("degradation path must not be used when synthesis succeeds")


class _RecordingPublisher:
    def __init__(self):
        self.published: list[tuple[ReportDraft, str]] = []

    def publish(self, state, draft, *, publication_status):
        self.published.append((draft, publication_status))
        return object()


def test_publish_via_assembly_happy_path_no_rejudge():
    state = _state()
    composer = _FakeAssembledComposer([_judgment()])
    publisher = _RecordingPublisher()
    report = publish_report_via_assembly(
        state, composer, publisher=publisher, tenant_id="t", run_id="r"
    )
    assert report is publisher.published[0][1] or report is not None
    draft, status = publisher.published[0]
    assert status == "grounded"
    assert state.budget.report_rejudgments_used == 0
    assert state.report_validation_errors == []
    assert composer.rejudge_inputs == []


def test_publish_via_assembly_repairs_unsupported_verdict_with_unit_rejudge():
    state = _state()
    # Verdict cites nothing resolvable: assembly drops it and the validator
    # flags verdict_without_support -> one minimal-edit re-judgment fixes it.
    broken = _judgment(verdict_refs=["ghost"], units=[])
    fixed = _judgment(units=[])
    composer = _FakeAssembledComposer([broken, fixed])
    publisher = _RecordingPublisher()
    publish_report_via_assembly(state, composer, publisher=publisher)
    assert state.budget.report_rejudgments_used == 1
    _judgment_seen, issues = composer.rejudge_inputs[0]
    assert any(issue.code == "verdict_without_support" for issue in issues)
    draft, status = publisher.published[0]
    assert status == "grounded"
    assert draft.verdict.supporting_refs == ["activity-raw-001", "activity-raw-002"]


def test_publish_via_assembly_falls_back_when_rejudgment_exhausted():
    state = _state()
    state.budget.max_report_rejudgments = 1
    broken = _judgment(verdict_refs=["ghost"], units=[])
    still_broken = _judgment(verdict_refs=["ghost"], units=[])
    composer = _FakeAssembledComposer([broken, still_broken])
    publisher = _RecordingPublisher()
    report = publish_report_via_assembly(state, composer, publisher=publisher)
    assert report is not None
    draft, status = publisher.published[0]
    assert status == "fallback"
    assert draft.verdict.level.value == "insufficient_evidence"
    assert state.report_validation_errors


def test_publish_via_assembly_degrades_to_legacy_on_synthesis_failure():
    state = _state()
    composer = _FakeAssembledComposer([RuntimeError("no structured output after 3 attempts")])
    assert publish_report_via_assembly(state, composer) is None


def test_publish_investigation_report_dispatches_by_pipeline_attribute():
    state = _state()
    composer = _FakeAssembledComposer([_judgment()])
    publisher = _RecordingPublisher()
    report = publish_investigation_report(
        state, composer, publisher=publisher, tenant_id="t", run_id="r"
    )
    assert report is not None
    assert len(publisher.published) == 1
    assert publisher.published[0][1] == "grounded"


def test_assembled_composer_builds_from_model_without_tools():
    class _JsonModeModel:
        model_name = "fake-json"

        def with_structured_output(self, schema, **kwargs):
            return self

    composer = AssembledReportComposer(_JsonModeModel(), None)
    assert composer.pipeline == "assembled"
    assert composer.legacy is not None
    assert composer.model_name == "fake-json"
