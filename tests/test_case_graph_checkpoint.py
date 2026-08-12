import json
from pathlib import Path

from threat_agent.case_management import CaseGraph
from threat_agent.case_management import create_memory_checkpointer, create_sqlite_checkpointer
from threat_agent.case_management import initialize_state
from threat_agent.judgment import JudgmentGraph
from threat_agent.judgment.application.planner import DeterministicPlanner
from threat_agent.data_foundation.adapters.repository import JsonlEventRepository
from threat_agent.judgment.adapters.tools import ToolRegistry


ROOT = Path(__file__).resolve().parents[1]


def build_case_graph(case_name: str, checkpointer):
    case_dir = ROOT / "cases" / case_name
    raw = json.loads((case_dir / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    registry = ToolRegistry(JsonlEventRepository(case_dir))
    judgment = JudgmentGraph(
        registry,
        DeterministicPlanner(),
        scope_approval_mode="defer",
    )
    return state, CaseGraph(judgment, checkpointer=checkpointer)


def test_parent_graph_interrupts_and_resumes_scope_approval():
    state, graph = build_case_graph("cross_host_scope_denied", create_memory_checkpointer())
    paused = graph.start(state, tenant_id="tenant-a", run_id="run-a")
    assert paused["lifecycle_status"] == "awaiting_scope_approval"
    assert paused["__interrupt__"]

    completed = graph.resume_scope(
        tenant_id="tenant-a",
        case_id=state.case_id,
        run_id="run-a",
        approved=False,
        approved_by="analyst@example.test",
    )
    assert completed["lifecycle_status"] == "judged"
    assert completed["judgment_result"] is not None
    assert completed["approval_status"] == "denied"
    assert completed["investigation"].scope_expansions[-1].approval_status == "denied"


def test_sqlite_checkpointer_restores_run_with_new_graph_instance(tmp_path):
    checkpoint_path = tmp_path / "case-checkpoints.sqlite"
    state, first = build_case_graph(
        "cross_host_scope_denied", create_sqlite_checkpointer(checkpoint_path)
    )
    paused = first.start(state, tenant_id="tenant-a", run_id="durable")
    calls_before_resume = len(paused["investigation"].tool_calls)
    first.compiled.checkpointer.conn.close()

    _state, restored = build_case_graph(
        "cross_host_scope_denied", create_sqlite_checkpointer(checkpoint_path)
    )
    completed = restored.resume_scope(
        tenant_id="tenant-a",
        case_id=state.case_id,
        run_id="durable",
        approved=False,
        approved_by="restored-analyst",
    )
    assert completed["lifecycle_status"] == "judged"
    assert len(completed["investigation"].tool_calls) >= calls_before_resume
    assert sum(
        call.tool_name == "scope_request" for call in completed["investigation"].tool_calls
    ) == 1
    restored.compiled.checkpointer.conn.close()


def test_checkpoint_thread_ids_isolate_tenants():
    saver = create_memory_checkpointer()
    state_a, graph_a = build_case_graph("c2_benign", saver)
    state_b, graph_b = build_case_graph("c2_benign", saver)
    result_a = graph_a.start(state_a, tenant_id="tenant-a", run_id="same")
    result_b = graph_b.start(state_b, tenant_id="tenant-b", run_id="same")
    assert result_a["judgment_result"].tenant_id == "tenant-a"
    assert result_b["judgment_result"].tenant_id == "tenant-b"
