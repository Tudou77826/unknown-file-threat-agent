"""Report input v2 (context archive design §4.4).

Gates:

- the compose input is case background + all archive cards + the projection
  of the not-yet-archived tail + the evidence catalog + the unchanged
  grounding instructions;
- archived activity queries leave the tail (exact query_id match), archived
  traces are consumed chronologically per (tool, arguments) so repeated
  identical calls split correctly between archive and tail;
- entity/metric/raw results are only dropped when every citable object they
  produced is provably inside the archive — anything unmatched stays
  (conservative direction: never lose information from the report input);
- without a memory store the context degrades to the full ledger tail
  (v1 shape for store-less callers).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from threat_agent.case_management import initialize_state
from threat_agent.contracts import (
    ActivityQueryResult,
    QueryExecutionBoundary,
    QueryInterfaceDefinition,
    QueryScopeSnapshot,
    Scope,
)
from threat_agent.contracts.activity import (
    NetworkActivity,
    ObservedRelation,
)
from threat_agent.contracts.investigation_tools import (
    ActivityMetricResult,
    EntityExplorationResult,
    InvestigationToolTrace,
)
from threat_agent.judgment.application.memory_store import MemoryStore
from threat_agent.judgment.application.reporting import report_context

NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)


def _activity(activity_id: str) -> NetworkActivity:
    return NetworkActivity(
        tenant_id="tenant-a", activity_id=activity_id, observed_at=NOW,
        ingested_at=NOW, source_system="test", source_record_id=f"r-{activity_id}",
        subject_refs=["host:host-1"], raw_record_ref=f"raw-{activity_id}",
        normalizer_version="1", host_ref="host-1",
        process_ref="process:host-1:1:1", operation="connect", direction="outbound",
    )


def _query_result(query_id: str, activity_ids: list[str]) -> ActivityQueryResult:
    scope = QueryScopeSnapshot(host_refs=["host-1"])
    return ActivityQueryResult(
        tenant_id="tenant-a", case_id="case-a", source_identity="test",
        run_id="run-a", query_id=query_id,
        interface_definition=QueryInterfaceDefinition(
            tenant_id="tenant-a", interface_id="activity-query/network",
            interface_version="1", activity_types=["network"],
            fields=[{"name": "activity_id", "value_type": "string",
                     "semantic": "id", "nullable": False}],
            max_page_size=1000,
        ),
        execution_boundary=QueryExecutionBoundary(
            interface_id="activity-query/network", interface_version="1",
            requested_scope=scope, applied_scope=scope,
            returned_count=len(activity_ids), page_limit=10, executed_at=NOW,
        ),
        activities=[_activity(a) for a in activity_ids],
        evidence_references=[],
    )


def _relation(relation_id: str) -> ObservedRelation:
    return ObservedRelation(
        tenant_id="tenant-a", relation_id=relation_id, relation_type="connected",
        source_entity_ref="process:host-1:1:1", target_entity_ref="endpoint:198.51.100.9:443",
        supporting_activity_refs=["act-a1"], resolution_status="resolved",
        confidence=0.9, resolver_version="1",
    )


def _entity_result(*, relation_id: str, timeline_id: str) -> EntityExplorationResult:
    return EntityExplorationResult(
        resolved_relations=[_relation(relation_id)],
        timeline=[_activity(timeline_id)],
        returned_count=1,
    )


def _trace(sequence: int, tool_name: str, arguments: dict) -> InvestigationToolTrace:
    return InvestigationToolTrace(
        sequence=sequence, tool_name=tool_name, arguments=arguments,
        result_type="ActivityQueryResult", result={"query_id": "q"},
    )


def _archived_store() -> MemoryStore:
    store = MemoryStore()
    store.record_archive(
        summary="进程与实体关联查证闭环，未见异常",
        round_span=(1, 2),
        rounds=[
            {"round": 1, "thinking": "t1", "tool_calls": [{
                "tool": "query_process_activities", "args": {},
                "args_digest": "", "returned": 1,
                "ids": {"queries": ["q-archived"], "activities": ["act-a1"],
                        "evidence": ["ev-1"]},
                "negative": False, "error": None,
            }]},
            {"round": 2, "thinking": "t2", "tool_calls": [{
                "tool": "explore_entity", "args": {"entity_ref": "e-1"},
                "args_digest": "entity_ref=e-1", "returned": 1,
                "ids": {"relations": ["rel-1"], "activities": ["act-e1"]},
                "negative": False, "error": None,
            }]},
        ],
        snapshots=[],
        records={},
    )
    return store


def _state():
    state = initialize_state({
        "File_id": "file-a", "File_hash": "a" * 64, "File_path": "/tmp/a",
        "Sub_asset": "host-1", "tenant_id": "tenant-a", "run_id": "run-a",
    })
    state.scope = Scope(host_ids=["host-1"])
    ledger = state.tool_ledger
    # The gateway maintains the authorized-ref whitelist; seed it like a real
    # run would after these queries returned.
    ledger.authorized_activity_refs.extend(
        ["act-a1", "act-a2", "act-e1", "act-e2"]
    )
    ledger.query_results.extend([
        _query_result("q-archived", ["act-a1"]),
        _query_result("q-tail", ["act-a2"]),
    ])
    ledger.entity_results.extend([
        _entity_result(relation_id="rel-1", timeline_id="act-e1"),  # covered
        _entity_result(relation_id="rel-2", timeline_id="act-e2"),  # tail
    ])
    ledger.metric_results.extend([
        ActivityMetricResult(operation="connection_pattern",
                             activity_refs=["act-a1"], metrics={}),
        ActivityMetricResult(operation="connection_pattern",
                             activity_refs=["act-a2"], metrics={}),
    ])
    ledger.traces.extend([
        _trace(1, "query_process_activities", {}),        # archived
        _trace(2, "explore_entity", {"entity_ref": "e-1"}),  # archived
        _trace(3, "query_network_activities", {}),        # tail
        _trace(4, "query_process_activities", {}),        # tail (repeat call, only one archived)
    ])
    return state


def test_v2_input_is_background_cards_tail_and_catalog():
    context = report_context(_state(), memory_store=_archived_store())

    # Case background replaces nothing — it is added context.
    assert context["case_background"]["case_input"]["File_id"] == "file-a"
    assert context["case_background"]["authorized_scope"]["host_ids"] == ["host-1"]

    # All archive cards ride along with their deterministic appendix.
    assert len(context["archive_cards"]) == 1
    card = context["archive_cards"][0]
    assert card["archive_id"] == "arc-1"
    assert card["summary"] == "进程与实体关联查证闭环，未见异常"
    assert card["round_span"] == [1, 2]
    assert [q["tool"] for q in card["queries"]] == [
        "query_process_activities", "explore_entity",
    ]
    assert card["queries"][0]["produced_ids"]["queries"] == ["q-archived"]
    assert card["queries"][1]["args_digest"] == "entity_ref=e-1"

    # Tail projection: only the not-yet-archived entries remain.
    assert [r["query_id"] for r in context["query_results"]] == ["q-tail"]
    assert len(context["entity_results"]) == 1
    assert context["entity_results"][0]["resolved_relations"][0]["relation_id"] == "rel-2"
    assert [m["activity_refs"] for m in context["metric_results"]] == [["act-a2"]]
    assert [t["tool_name"] for t in context["tool_traces"]] == [
        "query_network_activities", "query_process_activities",
    ]

    # The citable-ID whitelist still covers archived and tail content alike.
    catalog = context["evidence_catalog"]
    assert "act-a1" in catalog["citable_activity_ids"]
    assert "act-a2" in catalog["citable_activity_ids"]
    assert catalog["executed_query_ids"] == ["q-archived", "q-tail"]

    # Grounding instructions survived; archive semantics were appended.
    instructions = context["instructions"]
    assert any("returned_count=0" in item for item in instructions)
    assert any("archive_cards" in item for item in instructions)
    assert any("evidence_catalog" in item for item in instructions)
    assert any("Simplified Chinese" in item for item in instructions)


def test_entity_result_with_partial_archive_coverage_stays_in_tail():
    state = _state()
    # Timeline references one archived and one unarchived activity: the
    # exploration must stay in the report input.
    state.tool_ledger.entity_results[0].timeline.append(_activity("act-uncovered"))
    context = report_context(state, memory_store=_archived_store())
    kept = {r["resolved_relations"][0]["relation_id"] for r in context["entity_results"]}
    assert kept == {"rel-1", "rel-2"}


def test_without_a_store_the_input_degrades_to_the_full_ledger_tail():
    context = report_context(_state())
    assert context["archive_cards"] == []
    assert [r["query_id"] for r in context["query_results"]] == ["q-archived", "q-tail"]
    assert len(context["entity_results"]) == 2
    assert len(context["tool_traces"]) == 4


# -- trace coverage joins on execution order / call ids, never on arguments --


def test_trace_matching_survives_gateway_argument_normalization():
    # The gateway normalizes arguments before recording traces (datetime
    # formats, default fills); the archived card keeps the model-emitted
    # arguments. The join must not depend on argument equality.
    state = _state()
    store = MemoryStore()
    store.record_archive(
        summary="归档了一轮查询",
        round_span=(1, 1),
        rounds=[{"round": 1, "thinking": "t", "tool_calls": [{
            "tool": "query_process_activities",
            "tool_call_id": None,
            # Model-emitted form: +00:00 offset, no defaults.
            "args": {"host_refs": ["host-01"], "end_time": "2026-04-23T03:26:40+00:00"},
            "args_digest": "", "returned": 1,
            "ids": {"queries": ["q-archived"], "activities": ["act-a1"]},
            "negative": False, "error": None,
        }]}],
        snapshots=[],
        records={},
    )
    context = report_context(state, memory_store=store)
    # The archived call's trace left the tail even though its recorded
    # arguments differ from the card's; the later repeat call stays.
    assert [t["tool_name"] for t in context["tool_traces"]] == [
        "explore_entity", "query_network_activities", "query_process_activities",
    ]
    assert [r["query_id"] for r in context["query_results"]] == ["q-tail"]


def test_denied_calls_never_consume_trace_coverage():
    state = _state()
    store = MemoryStore()
    store.record_archive(
        summary="一轮里两次尝试，一次被边界拒绝",
        round_span=(1, 1),
        rounds=[{"round": 1, "thinking": "t", "tool_calls": [
            # Successful call: joins the coverage queue.
            {"tool": "query_process_activities", "tool_call_id": None, "args": {},
             "args_digest": "", "returned": 1,
             "ids": {"queries": ["q-archived"], "activities": ["act-a1"]},
             "negative": False, "error": None},
            # Denied call: no gateway trace exists, must not consume.
            {"tool": "query_process_activities", "tool_call_id": None,
             "args": {"host_refs": ["other-host"]},
             "args_digest": "host_refs=other-host", "returned": None, "ids": {},
             "negative": True, "error": "BoundaryDenied: host_out_of_scope"},
        ]}],
        snapshots=[],
        records={},
    )
    context = report_context(state, memory_store=store)
    # Exactly one successful archived call: only trace sequence 1 is
    # consumed; the denied twin consumed nothing, so 2-4 remain in the tail.
    assert [t["sequence"] for t in context["tool_traces"]] == [2, 3, 4]


def test_traces_with_call_ids_match_exactly():
    state = _state()
    store = MemoryStore()
    store.record_archive(
        summary="按 tool_call_id 精确对齐",
        round_span=(1, 1),
        rounds=[{"round": 1, "thinking": "t", "tool_calls": [{
            "tool": "query_process_activities", "tool_call_id": "call-1",
            "args": {}, "args_digest": "", "returned": 1,
            "ids": {"queries": ["q-archived"], "activities": ["act-a1"]},
            "negative": False, "error": None,
        }]}],
        snapshots=[],
        records={},
    )
    state.tool_ledger.traces[0].tool_call_id = "call-1"
    state.tool_ledger.traces[3].tool_call_id = "call-4"
    context = report_context(state, memory_store=store)
    assert [t["sequence"] for t in context["tool_traces"]] == [2, 3, 4]


def test_tail_traces_carry_envelope_only_for_successful_calls():
    # Successful gateway results are already in the typed sections; the
    # trace keeps identity + shape, not the duplicated payload.
    context = report_context(_state(), memory_store=_archived_store())
    traces = context["tool_traces"]
    for trace in traces:
        assert set(trace) == {
            "sequence", "tool_name", "arguments", "result_type",
            "result", "tool_call_id",
        }
        assert isinstance(trace["result"], dict)
        # No successful trace re-embeds an activities/timeline payload.
        assert "activities" not in trace["result"]
        assert "timeline" not in trace["result"]


def test_failed_traces_keep_their_error_payload_verbatim():
    state = _state()
    state.tool_ledger.traces.append(InvestigationToolTrace(
        sequence=5, tool_name="query_network_activities",
        arguments={"host_refs": ["host-1"]},
        result_type="ToolError",
        result={"error_type": "BoundaryDenied", "error_message": "out of scope"},
    ))
    context = report_context(state)
    failed = [t for t in context["tool_traces"] if t["result_type"] == "ToolError"]
    assert len(failed) == 1
    assert failed[0]["result"] == {
        "error_type": "BoundaryDenied", "error_message": "out of scope",
    }


def test_tail_trace_arguments_with_datetime_are_json_safe():
    # 回归：网关把时间过滤参数规范化成 datetime 后记进 trace.arguments；
    # 尾段投影曾用裸 dict(trace.arguments) 把 datetime 漏进 composer 的
    # json.dumps，报告阶段整案崩溃（demo L0/L1/L2 五案 TypeError）。
    state = _state()
    state.tool_ledger.traces.append(InvestigationToolTrace(
        sequence=5, tool_name="query_network_activities",
        arguments={"host_refs": ["host-1"], "start_time": NOW, "end_time": NOW},
        result_type="ActivityQueryResult", result={"query_id": "q-tail"},
    ))
    context = report_context(state, memory_store=_archived_store())
    payload = json.dumps(context, ensure_ascii=False)  # 不得抛 TypeError
    assert "2026-08-12T00:00:00" in payload  # datetime 以 ISO 字符串进入输入


def test_unarchived_input_shrinks_with_the_trace_projection():
    full = json.dumps(report_context(_state()), ensure_ascii=False)
    # Rebuild with the pre-projection shape to compare: every successful
    # trace carrying its full payload again.
    v1_style = report_context(_state())
    v1_style["tool_traces"] = [
        {
            "sequence": t["sequence"], "tool_name": t["tool_name"],
            "arguments": t["arguments"], "result_type": t["result_type"],
            "tool_call_id": t["tool_call_id"],
            "result": (
                {"query_id": "q-archived", "activities": [{"activity_id": "act-a1",
                  "command_line": "x" * 400, "subject_refs": ["host:host-1"]}]}
                if t["result_type"] != "ToolError" else t["result"]
            ),
        }
        for t in v1_style["tool_traces"]
    ]
    bloated = json.dumps(v1_style, ensure_ascii=False)
    assert len(full) < len(bloated)
