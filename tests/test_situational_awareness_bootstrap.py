from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from middleware_harness import TENANT, ScriptedModel, seed_store
from threat_agent.bootstrap import demo, workbench_bindings
from threat_agent.bootstrap.settings import AppSettings
from threat_agent.case_management import SQLiteInvestigationRuntimeStore, initialize_state
from threat_agent.contracts import InvestigationRun, RunExecutionRequest, Scope, ToolRuntimeContext
from threat_agent.data_foundation import SQLiteInvestigationDataAdapter, SituationalAwarenessDataAdapter


RAW_ALERT = {"File_hash": "a" * 64, "File_path": "/tmp/a", "Sub_asset": "host-1"}


@pytest.fixture
def settings(tmp_path):
    return AppSettings.load(env_file=tmp_path / "missing.env", environ={
        "THREAT_AGENT_DEFAULT_TENANT": TENANT,
        "THREAT_AGENT_CHECKPOINT_BACKEND": "memory",
        "KNOWLEDGE_ADAPTER": "null",
        "THREAT_AGENT_OBSERVABILITY_BACKEND": "none",
    })


def _no_local_store(*args, **kwargs):
    raise AssertionError("An injected data port must not open a local activity database")


def test_real_assembly_uses_injected_data_in_the_tool_gateway(tmp_path, monkeypatch, settings):
    store = seed_store(tmp_path)
    try:
        data = SituationalAwarenessDataAdapter(SQLiteInvestigationDataAdapter(store))
        for name in ("build_judgment_model", "build_report_model", "build_response_model"):
            monkeypatch.setattr(demo, name, lambda settings: ScriptedModel(messages=iter([])))
        gateways = []
        original_gateway = demo.InvestigationToolGateway

        def capture_gateway(*args, **kwargs):
            gateway = original_gateway(*args, **kwargs)
            gateways.append(gateway)
            return gateway

        monkeypatch.setattr(demo, "InvestigationToolGateway", capture_gateway)
        monkeypatch.setattr(demo, "SQLiteActivityStore", _no_local_store)
        state = initialize_state(RAW_ALERT)
        state.scope = Scope(host_ids=["host-1"])
        assembly = demo.assemble_investigation_run(
            state=state, settings=settings, run_id="run-a", investigation_data=data,
        )
        gateway = gateways[0]
        result = gateway.invoke(
            "query_process_activities", {},
            ToolRuntimeContext(tenant_id=TENANT, case_id=state.case_id, run_id="run-a", scope=state.scope),
            state.tool_ledger,
        )
        assert [activity.activity_id for activity in result.activities] == ["activity-p1"]
        assembly.close()
        # The assembly does not own the shared, injected source.
        assert data.get_raw_record(TENANT, "activity-p1") is not None
    finally:
        store.close()


def test_assembly_rejects_missing_data_or_unapplied_profile(settings):
    state = initialize_state(RAW_ALERT)
    with pytest.raises(ValueError, match="required"):
        demo.assemble_investigation_run(state=state, settings=settings, run_id="run-a")
    with pytest.raises(ValueError, match="visibility"):
        demo.assemble_investigation_run(
            state=state, settings=settings, run_id="run-a",
            investigation_data=SituationalAwarenessDataAdapter(), visible_sources={"edr-process"},
        )


def test_alert_execution_and_checkpoint_rebuild_use_the_injected_port(monkeypatch, settings):
    data = SituationalAwarenessDataAdapter()
    calls = []

    def assemble(activity_store, **kwargs):
        assert activity_store is None
        calls.append(kwargs["investigation_data"])
        return SimpleNamespace(
            graph=SimpleNamespace(start=lambda *args, **kwargs: {}),
            tenant_id=TENANT, close=lambda: None,
        )

    monkeypatch.setattr(workbench_bindings, "SQLiteActivityStore", _no_local_store)
    monkeypatch.setattr(workbench_bindings, "assemble_investigation_run", assemble)
    request = RunExecutionRequest(tenant_id=TENANT, case_id="case-a", run_id="run-a",
                                  source="alert_json", alert=RAW_ALERT)
    execution = workbench_bindings.AlertExecution(settings, investigation_data=data)
    outcome = execution.execute(request, emit=lambda *args: None)
    assert outcome.artifacts["alert_payload"] == RAW_ALERT
    checkpoints = workbench_bindings.AlertCheckpointAccess(settings, investigation_data=data)
    monkeypatch.setattr(checkpoints, "_request_alert", lambda request: RAW_ALERT)
    checkpoints._assemble(request, emit=None).close()
    assert calls == [data, data]


def test_local_checkpoint_store_stays_open_until_assembly_close(tmp_path, monkeypatch, settings):
    from threat_agent.bootstrap.settings import WorkbenchSettings

    settings = settings.model_copy(update={"workbench": WorkbenchSettings(
        alert_activity_store_path=tmp_path / "local.sqlite",
    )})
    opened = []

    def assemble(activity_store, **kwargs):
        opened.append(activity_store)
        return SimpleNamespace(activity_store=activity_store, close=activity_store.close)

    monkeypatch.setattr(workbench_bindings, "assemble_investigation_run", assemble)
    checkpoints = workbench_bindings.AlertCheckpointAccess(settings)
    monkeypatch.setattr(checkpoints, "_request_alert", lambda request: RAW_ALERT)
    assembly = checkpoints._assemble(
        RunExecutionRequest(tenant_id=TENANT, case_id="case-a", run_id="run-a"), emit=None,
    )
    try:
        assert opened[0].connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        assembly.close()


def test_approval_and_debug_keep_alert_source_and_the_same_adapter(tmp_path, settings):
    data = SituationalAwarenessDataAdapter()
    store = SQLiteInvestigationRuntimeStore(tmp_path / "runtime.sqlite")
    try:
        service = workbench_bindings.build_run_service(settings, runtime_store=store, investigation_data=data)
        approval = workbench_bindings.build_approval_service(settings, service)
        debug = workbench_bindings.build_debug_service(settings, service)
        assert approval.approvals.alert.investigation_data is data
        assert debug.checkpoints.alert.investigation_data is data
        for run_id, dataset_id, alert in (("alert-run", "", RAW_ALERT), ("ref-run", "dataset-a", {})):
            store.create_run(InvestigationRun(
                tenant_id=TENANT, case_id="case-a", run_id=run_id, status="completed", stage="published",
                graph_thread_id=f"{TENANT}/case-a/{run_id}", started_at=datetime.now(timezone.utc),
            ), dataset_id=dataset_id, profile_id="")
            store.put_artifact(TENANT, run_id, "alert_payload", alert)
            expected = "alert_json" if run_id == "alert-run" else "reference_dataset"
            assert approval._request(run_id).source == expected
            assert debug._request(run_id).source == expected
    finally:
        store.close()
