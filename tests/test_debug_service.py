"""Feature 17 step 02 — debug surface: checkpoint time travel and audit."""

from __future__ import annotations

from pathlib import Path

from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import AIMessage
from langgraph.graph import END, START, StateGraph

from threat_agent.bootstrap.middleware_runtime import MiddlewareJudgmentRunner
from threat_agent.case_management import (
    CaseGraph,
    DebugService,
    RunService,
    RunServiceConfig,
    SingleHostBoundaryPolicy,
    SQLiteInvestigationRuntimeStore,
    create_sqlite_checkpointer,
    initialize_state,
)
from threat_agent.contracts import (
    CheckpointRef,
    RunExecutionRequest,
    Scope,
    ToolRuntimeContext,
)
from threat_agent.data_foundation import SQLiteInvestigationDataAdapter

from threat_agent.judgment import InvestigationToolGateway
from threat_agent.data_foundation import SQLiteInvestigationDataAdapter

from middleware_harness import RUN, TENANT, ScriptedModel, seed_store

SCRIPT = [
    ("query_process_activities", {}),
    ("query_network_activities", {}),
]

# A cycling script: the first pass consumes tool calls then "done"; a debug
# replay re-executes nodes and keeps drawing from the same endless sequence.
import itertools  # noqa: E402


def _script_messages():
    def gen():
        while True:
            for index, (name, arguments) in enumerate(SCRIPT):
                yield AIMessage(content="", tool_calls=[{
                    "name": name, "args": dict(arguments),
                    "id": f"call-{next(_counter)}", "type": "tool_call",
                }])
            yield AIMessage(content="done")

    _counter = itertools.count()
    return gen()


def _state():
    state = initialize_state({
        "File_id": "file-a", "File_hash": "a" * 64, "File_path": "/tmp/a",
        "Sub_asset": "host-1",
    })
    state.scope = Scope(host_ids=["host-1"])
    return state


def _graph_with_sqlite_checkpointer(checkpoint_path: Path):
    store = seed_store(Path(checkpoint_path).parent / "seed")
    state = _state()
    policy = SingleHostBoundaryPolicy(tenant_id=TENANT, case_id=state.case_id, run_id=RUN)
    runner = MiddlewareJudgmentRunner(
        model=ScriptedModel(messages=_script_messages()),
        summarizer_model=FakeListChatModel(responses=["摘要"]),
        gateway=InvestigationToolGateway(SQLiteInvestigationDataAdapter(store), policy),
        boundary_policy=policy,
        context=ToolRuntimeContext(
            tenant_id=TENANT, case_id=state.case_id, run_id=RUN,
            scope=Scope(host_ids=["host-1"]),
        ),
        ledger=state.tool_ledger,
        case_budget=state.budget,
        report_composer=SimpleComposer(),
        emit=lambda *args, **kwargs: None,
        context_window_tokens=800,
        recursion_limit=100,
    )
    graph = CaseGraph(runner, checkpointer=create_sqlite_checkpointer(checkpoint_path))
    return graph, state, store


class SimpleComposer:
    """Ungrounded on purpose: the pipeline publishes the fallback report."""

    model_name = "stub-composer"

    def compose_draft(self, state):
        from threat_agent.contracts.investigation import CandidateVerdict
        from threat_agent.judgment.application.report_draft import ReportDraft

        return ReportDraft(
            verdict=CandidateVerdict(
                level="confirmed_malicious",
                threat_type="backdoor_c2",
                summary="stub draft",
                supporting_refs=["activity-does-not-exist"],
            ),
            executive_summary="stub draft",
        )

    def rejudge(self, state, previous_draft, issues, *, attempt):
        return previous_draft


def test_time_travel_lists_history_and_replays_from_a_mid_checkpoint(tmp_path: Path):
    checkpoint_path = tmp_path / "checkpoints.sqlite"
    graph, state, store = _graph_with_sqlite_checkpointer(checkpoint_path)
    try:
        result = graph.start(state, tenant_id=TENANT, run_id=RUN)
        assert result["lifecycle_status"] in ("judged", "complete")

        snapshots = graph.state_history(tenant_id=TENANT, case_id=state.case_id, run_id=RUN)
        assert len(snapshots) >= 3, "a completed run must leave a checkpoint trail"
        steps = [snapshot.metadata.get("step") for snapshot in snapshots]
        assert steps == sorted(steps, reverse=True), "history must be newest first"

        mid = snapshots[len(snapshots) // 2]
        checkpoint_id = str(mid.config["configurable"]["checkpoint_id"])
        replayed = graph.resume_from(
            tenant_id=TENANT,
            case_id=state.case_id,
            run_id=RUN,
            checkpoint_id=checkpoint_id,
            value=None,
        )
        assert replayed["lifecycle_status"] in ("judged", "complete")
    finally:
        store.close()


class FakeCheckpointPort:
    def __init__(self):
        self.resume_calls: list[tuple[str, object]] = []
        self.refs = [
            CheckpointRef(checkpoint_id="cp-1", step=1, node="intake"),
            CheckpointRef(checkpoint_id="cp-2", step=2, node="execute"),
        ]

    def list_checkpoints(self, request: RunExecutionRequest):
        return self.refs

    def state_summary(self, request: RunExecutionRequest, checkpoint_id: str):
        return self.refs[-1], None

    def resume(self, request: RunExecutionRequest, checkpoint_id: str, *, value, emit=None):
        self.resume_calls.append((checkpoint_id, value))
        return {"lifecycle_status": "complete"}


def test_debug_service_audits_resume_and_never_touches_run_rows(tmp_path: Path):
    store = SQLiteInvestigationRuntimeStore(tmp_path / "runtime.sqlite")
    from datetime import datetime, timezone

    from threat_agent.contracts import InvestigationRun

    store.create_run(
        InvestigationRun(
            tenant_id=TENANT, case_id="case-1", source_identity="test",
            run_id=RUN, status="completed", stage="published",
            graph_thread_id=f"{TENANT}/case-1/{RUN}",
            started_at=datetime.now(timezone.utc),
        ),
        dataset_id="dataset-a", profile_id="profile-a",
    )
    port = FakeCheckpointPort()
    emitted: list[tuple] = []
    service = DebugService(
        tenant_id=TENANT,
        checkpoints=port,
        runtime_store=store,
        emit=lambda run_id, kind, message, details=None: emitted.append((run_id, kind, details or {})),
    )
    try:
        refs = service.list_checkpoints(RUN)
        assert [ref.checkpoint_id for ref in refs] == ["cp-1", "cp-2"]

        result = service.resume(RUN, "cp-2", value=None)
        assert result == {"lifecycle_status": "complete"}
        assert port.resume_calls == [("cp-2", None)]
        run = store.get_run(TENANT, RUN)
        assert run.status == "completed", "debug replay must not migrate run state"
        audits = store.list_audit_events(TENANT, RUN)
        assert [item.action for item in audits] == ["debug_resumed"]
        debug_events = [details for _r, _k, details in emitted if details.get("debug_replay")]
        assert debug_events, "replay events must be marked as debug"
    finally:
        store.close()
