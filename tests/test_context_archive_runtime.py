"""Runner-level integration for context archive / recall (design v4 §8).

Exercises the real ``MiddlewareJudgmentRunner`` assembly end to end with a
shared ``MemoryStore``: the gateway tools execute for real, ``archive_context``
is intercepted by the middleware stack (budgeted like any tool call), the
interval is rewritten before the next model call, ``recall`` reads the same
store as a regular registered tool, and the real ``StructuredReportComposer``
composes from the v2 input — case background + archive cards + tail
projection + evidence catalog — through the untouched grounding/rejudge/
fallback chain.
"""

from __future__ import annotations

import json
from pathlib import Path

from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import AIMessage

from middleware_harness import RUN, TENANT, ScriptedModel, seed_store
from threat_agent.bootstrap.middleware_runtime import MiddlewareJudgmentRunner
from threat_agent.bootstrap.settings import AppSettings
from threat_agent.case_management import SingleHostBoundaryPolicy, initialize_state
from threat_agent.contracts import Scope, ToolRuntimeContext
from threat_agent.contracts.investigation import CandidateVerdict
from threat_agent.data_foundation import SQLiteInvestigationDataAdapter
from threat_agent.judgment import InvestigationToolGateway, StructuredReportComposer
from threat_agent.judgment.application.memory_store import MemoryStore
from threat_agent.judgment.application.report_draft import ReportDraft


def _call(index: int, name: str, arguments: dict) -> dict:
    return {"name": name, "args": arguments, "id": f"c{index}", "type": "tool_call"}


class _QueueStructuredModel:
    """Serve queued ReportDrafts and capture every prompt it sees."""

    model_name = "fake-report-model"

    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls: list[list] = []

    def with_structured_output(self, _schema, **_kwargs):
        outer = self

        class _Bound:
            def invoke(self, messages):
                outer.calls.append(messages)
                return outer.outputs.pop(0)

        return _Bound()


def _ungrounded_draft() -> ReportDraft:
    # Deliberately ungrounded: the pipeline must route through rejudge and
    # land on the deterministic fallback — proving those links still work on
    # the v2 input.
    return ReportDraft(
        verdict=CandidateVerdict(
            level="confirmed_malicious",
            threat_type="backdoor_c2",
            summary="stub draft",
            supporting_refs=["activity-does-not-exist"],
        ),
        executive_summary="stub draft",
        supporting_evidence_refs=["activity-does-not-exist"],
    )


def test_runner_archives_recalls_and_reports_from_cards(tmp_path: Path):
    store = seed_store(tmp_path / "seed")
    state = initialize_state({
        "File_id": "file-a", "File_hash": "a" * 64, "File_path": "/tmp/a",
        "Sub_asset": "host-1",
    })
    state.scope = Scope(host_ids=["host-1"])
    policy = SingleHostBoundaryPolicy(tenant_id=TENANT, case_id=state.case_id, run_id=RUN)
    events: list[tuple] = []
    # One archive memory per run: shared by the runner (archive + recall) and
    # the report composer, exactly like the demo assembly.
    memory_store = MemoryStore()
    report_model = _QueueStructuredModel([_ungrounded_draft() for _ in range(3)])
    report_composer = StructuredReportComposer(report_model, memory_store=memory_store)

    script = [
        AIMessage(content="", tool_calls=[_call(1, "query_process_activities", {})]),
        AIMessage(content="", tool_calls=[_call(2, "query_network_activities", {})]),
        AIMessage(content="收束", tool_calls=[_call(3, "archive_context", {
            "summary": "初步进程与外连查证完毕，未见异常，可收束归档",
        })]),
        AIMessage(content="", tool_calls=[_call(4, "recall", {"archives": ["arc-1"]})]),
        AIMessage(content="done"),
    ]
    settings = AppSettings.load(
        environ={},
        env_file=Path("__no_such_env_file__"),
        cli_overrides={
            # Two one-activity rounds are far below the default 1k-token
            # span estimate; lower the guardrail to exercise the wiring,
            # not the threshold (covered by the middleware tests).
            "ARCHIVE_MIN_SPAN_TOKENS": "1",
        },
    )
    runner = MiddlewareJudgmentRunner(
        model=ScriptedModel(messages=iter(script)),
        summarizer_model=FakeListChatModel(responses=["摘要"]),
        gateway=InvestigationToolGateway(
            SQLiteInvestigationDataAdapter(store), policy
        ),
        boundary_policy=policy,
        context=ToolRuntimeContext(
            tenant_id=TENANT, case_id=state.case_id, run_id=RUN,
            scope=Scope(host_ids=["host-1"]),
        ),
        ledger=state.tool_ledger,
        case_budget=state.budget,
        report_composer=report_composer,
        settings=settings,
        memory_store=memory_store,
        emit=lambda kind, message, details=None: events.append((kind, message, details)),
        context_window_tokens=100_000,
        recursion_limit=100,
    )

    result = runner.run(state)

    # -- archive: the interval landed in the run-scoped memory store -------
    memory = runner.memory_store
    assert memory is memory_store
    assert memory.handles() == ["arc-1"]
    assert memory.stats()["rounds_archived"] == 2
    block = memory.get_archive("arc-1")
    assert [record["round"] for record in block["rounds"]] == [1, 2]
    indexed = memory.card_index()[0]["ids"]
    assert indexed["activities"], "gateway activities must be indexed"

    # -- events: archive, recall and applied-rewrite flowed into the stream
    kinds = [(kind, details or {}) for kind, _, details in events]
    recorded = next(
        d for k, d in kinds
        if k == "context" and d.get("archive_id") == "arc-1" and d.get("tool_calls")
    )
    assert recorded["model_rounds"] == 2
    assert any(k == "context" and d.get("archive_id") == "arc-1"
               and "removed_messages" in d for k, d in kinds), "archive_applied missing"
    assert any(k == "recall" and d.get("entry") == "archives" for k, d in kinds)

    # -- report: the real composer saw the v2 input ------------------------
    assert report_model.calls, "composer was never invoked"
    compose_input = json.loads(report_model.calls[0][-1]["content"])
    cards = compose_input["archive_cards"]
    assert len(cards) == 1
    assert cards[0]["archive_id"] == "arc-1"
    assert cards[0]["summary"] == "初步进程与外连查证完毕，未见异常，可收束归档"
    assert [q["tool"] for q in cards[0]["queries"]] == [
        "query_process_activities", "query_network_activities",
    ]
    # Both queries are archived: the tail carries no full dump any more, the
    # catalog keeps every citable ID addressable.
    assert compose_input["query_results"] == []
    catalog_activities = compose_input["evidence_catalog"]["citable_activity_ids"]
    assert set(indexed["activities"]) <= set(catalog_activities)
    assert compose_input["case_background"]["case_input"]["File_id"] == "file-a"
    # The card-based input is strictly smaller than a full-ledger dump of the
    # same run (the §4.4 cost goal).
    from threat_agent.judgment.application.reporting import report_context
    full_dump = json.dumps(
        report_context(result, memory_store=None), ensure_ascii=False
    )
    card_input = json.dumps(
        report_context(result, memory_store=memory_store), ensure_ascii=False
    )
    assert len(card_input) < len(full_dump)

    # -- the untouched chain still published (fallback on the ungrounded draft)
    assert result.investigation_report is not None
    assert result.investigation_report.publication_status == "fallback"
    assert result.finished is True
