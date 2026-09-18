"""Feature 17 step 02 — trajectory projection: rounds as the spine."""

from __future__ import annotations

from threat_agent.case_management import (
    RunService,
    RunServiceConfig,
    SQLiteInvestigationRuntimeStore,
)
from threat_agent.case_management.application.trajectory import build_trajectory
from threat_agent.contracts import OperationalEvent


def _event(sequence: int, kind: str, message: str, *, node: str = "", **details) -> OperationalEvent:
    return OperationalEvent(
        tenant_id="demo", case_id="case-1", source_identity="test", run_id="run-1",
        event_id=f"event-{sequence:05d}", sequence=sequence,
        event_type="run", stage="investigating", node=node,
        token_usage=details.pop("token_usage", {}),
        retry_count=details.pop("retry_count", 0),
        details={"kind": kind, "message": message, **details},
        correlation_id="corr",
    )


def test_rounds_group_their_entries_and_lifecycle_events_stay_in_phases():
    events = [
        _event(1, "run", "初始化"),
        _event(2, "graph", "流程启动", node="intake"),
        _event(3, "tool", "查询进程", node="execute", query_id="query-1",
               token_usage={"input_tokens": 100, "output_tokens": 20}),
        _event(4, "round", "第 1 轮：确认了进程执行", round=1),
        _event(5, "tool", "查询网络", node="execute", query_id="query-2",
               token_usage={"input_tokens": 50}, retry_count=1),
        _event(6, "model_input", "规划输入", phase="judgment_planning"),
        _event(7, "round", "第 2 轮：确认了外联", round=2),
        _event(8, "verdict", "研判结论：确认恶意", node="gate"),
        _event(9, "complete", "完成"),
    ]
    trajectory = build_trajectory(events, run_id="run-1", case_id="case-1")

    assert [item.index for item in trajectory.rounds] == [1, 2]
    assert trajectory.rounds[0].observation == "第 1 轮：确认了进程执行"
    # The round marker summarizes work already done: tool events buffered
    # since the previous marker belong to the round being closed — including
    # the planning inputs issued between markers.
    assert [entry.event_id for entry in trajectory.rounds[0].entries] == ["event-00003"]
    assert [entry.event_id for entry in trajectory.rounds[1].entries] == [
        "event-00005", "event-00006",
    ]
    # Narrative/lifecycle markers stay in the phase lane.
    assert [entry.event_id for entry in trajectory.phase_entries] == [
        "event-00001", "event-00002", "event-00008", "event-00009",
    ]
    assert trajectory.rounds[0].entries[0].evidence_refs == ["query-1"]
    assert trajectory.totals["token_usage"] == {
        "input_tokens": 150, "output_tokens": 20,
    }
    assert trajectory.totals["retries"] == 1
    assert trajectory.totals["events"] == 9


def test_run_service_builds_trajectory_from_persisted_events(tmp_path):
    store = SQLiteInvestigationRuntimeStore(tmp_path / "runtime.sqlite")
    service = RunService(
        RunServiceConfig(tenant_id="demo"),
        execution=_NoExecution(),
        resolve_case=lambda dataset_id, profile_id: "case-1",
        runtime_store=store,
    )
    try:
        from datetime import datetime, timezone

        from threat_agent.contracts import InvestigationRun

        store.create_run(
            InvestigationRun(
                tenant_id="demo", case_id="case-1", source_identity="test",
                run_id="run-1", status="completed", stage="published",
                graph_thread_id="demo/case-1/run-1",
                started_at=datetime.now(timezone.utc),
            ),
            dataset_id="dataset-a", profile_id="profile-a",
        )
        service._emit("run-1", "tool", "查询进程", {"query_id": "query-1"})
        service._emit("run-1", "round", "第 1 轮完成", {"round": 1})

        trajectory = service.get_trajectory("run-1")
        assert trajectory is not None
        assert trajectory.run_id == "run-1"
        assert trajectory.rounds[0].observation == "第 1 轮完成"
        assert trajectory.rounds[0].entries[0].evidence_refs == ["query-1"]
        assert service.get_trajectory("missing") is None
    finally:
        service.close()


class _NoExecution:
    def execute(self, request, *, emit):  # pragma: no cover - guard
        raise AssertionError("execution must not run in this test")
