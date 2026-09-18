"""Feature 17 step 02 — observability sidecar: degradation and wiring."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

from threat_agent.bootstrap.settings import AppSettings
from threat_agent.bootstrap.workbench_bindings import ReferenceProfileExecution
from threat_agent.contracts import RunExecutionOutcome, RunExecutionRequest
from threat_agent.observability import NullTraceSink, build_trace_sink

REQUEST = RunExecutionRequest(
    tenant_id="demo", case_id="case-1", run_id="run-1",
    dataset_id="ds", profile_id="l3",
)


class _FakeResult:
    def model_dump(self, mode="json"):
        return {"ok": True}

    investigation_report = None

    class case:  # noqa: N801 - simple namespace stand-in
        response_plan = None
        judgment = None


def _install_fake_runner(monkeypatch, captured: dict):
    def fake_run_demo_profile(_store, **kwargs):
        captured.update(kwargs)
        return _FakeResult()

    import threat_agent.bootstrap.workbench_bindings as bindings

    monkeypatch.setattr(bindings, "run_demo_profile", fake_run_demo_profile)


def _execution(sink) -> ReferenceProfileExecution:
    return ReferenceProfileExecution(
        AppSettings.load(env_file=Path("__missing__.env")),
        project_root=Path("."),
        trace_sink=sink,
    )


class RaisingSink:
    def handler_for(self, **kwargs):
        raise RuntimeError("sink exploded")

    def close(self):
        return None


class SentinelSink:
    def __init__(self):
        self.handler = object()

    def handler_for(self, **kwargs):
        return self.handler

    def close(self):
        return None


def test_none_backend_builds_null_sink():
    assert isinstance(build_trace_sink("none"), NullTraceSink)
    assert build_trace_sink("none").handler_for(
        tenant_id="t", case_id="c", run_id="r", session_key="s", tags=[]
    ) is None


def test_langfuse_backend_degrades_to_null_when_package_missing():
    if importlib.util.find_spec("langfuse") is not None:
        return  # installed: degradation path is unreachable here
    assert isinstance(build_trace_sink("langfuse"), NullTraceSink)


def test_sink_failure_degrades_observation_and_never_blocks_the_run(monkeypatch):
    captured: dict = {}
    _install_fake_runner(monkeypatch, captured)
    emitted: list[tuple] = []
    outcome = _execution(RaisingSink()).execute(
        REQUEST, emit=lambda kind, message, details=None: emitted.append((kind, details or {}))
    )
    assert isinstance(outcome, RunExecutionOutcome)
    assert outcome.artifacts["demo_result"] == {"ok": True}
    degraded = [details for _kind, details in emitted if details.get("observability_degraded")]
    assert degraded, "sink failure must be observable as a degradation event"
    assert captured.get("trace_handler") is None


def test_healthy_sink_handler_is_passed_into_execution(monkeypatch):
    captured: dict = {}
    _install_fake_runner(monkeypatch, captured)
    emitted: list[tuple] = []
    sink = SentinelSink()
    _execution(sink).execute(
        REQUEST, emit=lambda kind, message, details=None: emitted.append((kind, details or {}))
    )
    assert captured.get("trace_handler") is sink.handler
    assert not [details for _k, details in emitted if details.get("observability_degraded")]
