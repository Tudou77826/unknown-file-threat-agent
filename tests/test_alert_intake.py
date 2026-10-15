from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

from middleware_harness import TENANT
from threat_agent.case_management import (
    AlertIntakeConfig, AlertIntakeConnector, SQLiteIntakeStateStore,
    SQLiteInvestigationRuntimeStore,
)
from threat_agent.case_management.application.alert_intake import map_alert_to_payload
from threat_agent.contracts import (
    FileHash, InvestigationRun, QueryPage, UnknownFileAlert,
)
from threat_agent.data_foundation import (
    DataQueryFailed, SituationalAwarenessDataAdapter, UnsupportedDataQuery,
)
from threat_agent.presentation.api.routes import create_app


NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
HOST = "host-1"
SHA = "a" * 64


def _alert(record_id: str, *, detected_at=None, digest=SHA, file_path="/tmp/a",
           algorithm="sha256", pid=11, process_name="python3") -> UnknownFileAlert:
    file_hash = FileHash(algorithm=algorithm, digest=digest) if digest else None
    return UnknownFileAlert(
        tenant_id=TENANT, source_system="siem", source_record_id=record_id,
        host_ref=HOST, detected_at=detected_at, file_path=file_path,
        file_hash=file_hash, pid=pid, process_name=process_name,
    )


def _config(**overrides) -> AlertIntakeConfig:
    values = dict(
        tenant_id=TENANT, host_ids=(HOST,), interval_seconds=300,
        max_runs_per_poll=5, alert_limit=50,
    )
    values.update(overrides)
    return AlertIntakeConfig(**values)


class RecordingSink:
    """Stand-in for RunService: creates the run row the audit FK requires."""

    def __init__(self, runtime_store, *, fail_records: set[str] | None = None):
        self.runtime_store = runtime_store
        self.fail_records = fail_records or set()
        self.payloads: list[dict[str, Any]] = []

    def start_alert(self, raw_alert: dict[str, Any]) -> str:
        if raw_alert.get("File_hash") in self.fail_records:
            raise RuntimeError("simulated run failure")
        run_id = f"run-{len(self.payloads) + 1:03d}"
        self.payloads.append(raw_alert)
        self.runtime_store.create_run(
            InvestigationRun(
                tenant_id=TENANT, case_id=f"case-{run_id}", run_id=run_id,
                status="queued", stage="intake",
                graph_thread_id=f"{TENANT}/case-x/{run_id}", started_at=NOW,
            ),
            dataset_id="", profile_id="",
        )
        return run_id


@pytest.fixture
def runtime_store(tmp_path):
    store = SQLiteInvestigationRuntimeStore(tmp_path / "runtime.sqlite")
    yield store
    store.close()


@pytest.fixture
def state_store(tmp_path):
    store = SQLiteIntakeStateStore(tmp_path / "intake-state.sqlite")
    yield store
    store.close()


def _connector(alerts_handler, sink, state, runtime_store, *, clock=None, **config):
    source = SituationalAwarenessDataAdapter(alerts=alerts_handler)
    return AlertIntakeConnector(
        source, sink, state, runtime_store, _config(**config),
        clock=clock or (lambda: NOW),
    )


def test_new_alert_creates_run_maps_fields_advances_watermark_and_audits(
    runtime_store, state_store
):
    detected = NOW - timedelta(minutes=1)
    sink = RecordingSink(runtime_store)
    connector = _connector(
        lambda query: QueryPage(records=[_alert("alert-1", detected_at=detected)]),
        sink, state_store, runtime_store,
    )

    report = connector.poll_once()

    assert report.created_run_ids == ["run-001"]
    assert report.skipped == [] and report.failed == []
    assert report.watermark == detected
    payload = sink.payloads[0]
    assert payload["File_hash"] == SHA
    assert payload["File_path"] == "/tmp/a"
    assert payload["Sub_asset"] == HOST
    assert payload["source"] == "siem"
    assert payload["discovery_time"] == int(detected.timestamp() * 1000)
    assert payload["Detail"] == {"context": [{"pid": 11, "path": "python3"}]}
    audit = runtime_store.list_audit_events(TENANT, "run-001")
    assert [event.action for event in audit] == ["intake_alert_accepted"]
    assert audit[0].resource_ref == "siem/alert-1"
    # A second round with the same alert dedups instead of creating another run.
    assert connector.poll_once().created_run_ids == []
    assert len(sink.payloads) == 1


def test_state_survives_connector_restart(runtime_store, state_store, tmp_path):
    detected = NOW - timedelta(minutes=1)
    sink = RecordingSink(runtime_store)
    handler = lambda query: QueryPage(records=[_alert("alert-1", detected_at=detected)])
    _connector(handler, sink, state_store, runtime_store).poll_once()

    restarted = _connector(
        handler, RecordingSink(runtime_store), state_store, runtime_store
    )
    report = restarted.poll_once()
    assert report.created_run_ids == []
    assert restarted.state.get_watermark(TENANT) == detected


def test_skip_rules_record_state_and_do_not_repeat(runtime_store, state_store):
    calls = {"handler": 0, }

    def handler(query):
        calls["handler"] += 1
        return QueryPage(records=[
            _alert("no-hash", detected_at=NOW - timedelta(minutes=2), digest=None),
            _alert("md5", detected_at=NOW - timedelta(minutes=2),
                   digest="b" * 32, algorithm="md5"),
            _alert("no-path", detected_at=NOW - timedelta(minutes=2), file_path=None),
        ])

    sink = RecordingSink(runtime_store)
    connector = _connector(handler, sink, state_store, runtime_store)

    report = connector.poll_once()
    assert report.created_run_ids == []
    assert sorted(report.skipped) == [
        "siem/md5", "siem/no-hash", "siem/no-path",
    ]
    assert state_store.retryable_keys(TENANT) == set()
    events = [e for e in state_store.list_recent_events(TENANT)
              if e["kind"] == "intake_alert_skipped"]
    assert len(events) == 3

    connector.poll_once()
    skipped_after = [e for e in state_store.list_recent_events(TENANT)
                     if e["kind"] == "intake_alert_skipped"]
    assert len(skipped_after) == 3  # no repeated skipping


def test_over_limit_alerts_wait_for_the_next_round(runtime_store, state_store):
    alerts = [
        _alert(f"alert-{index}", detected_at=NOW - timedelta(minutes=10 - index))
        for index in range(1, 8)
    ]
    sink = RecordingSink(runtime_store)
    handler = lambda query: QueryPage(records=alerts)
    clock = {"now": NOW}
    connector = _connector(
        handler, sink, state_store, runtime_store,
        clock=lambda: clock["now"], max_runs_per_poll=5,
    )

    first = connector.poll_once()
    assert len(first.created_run_ids) == 5
    assert first.watermark == alerts[4].detected_at

    clock["now"] = NOW + timedelta(minutes=5)
    second = connector.poll_once()
    # The two alerts beyond the first cap are both processed in round two.
    assert second.created_run_ids == ["run-006", "run-007"]
    assert second.watermark == alerts[6].detected_at


def test_failed_query_keeps_watermark_and_retries(runtime_store, state_store):
    def handler(query):
        raise TimeoutError("source connection details")

    sink = RecordingSink(runtime_store)
    connector = _connector(handler, sink, state_store, runtime_store)

    report = connector.poll_once()
    assert report.error and "source query failed" in report.error
    assert report.watermark is None
    assert state_store.get_watermark(TENANT) is None
    events = [e for e in state_store.list_recent_events(TENANT)
              if e["kind"] == "intake_poll_failed"]
    assert len(events) == 1


def test_unsupported_source_disables_the_connector(runtime_store, state_store):
    connector = AlertIntakeConnector(
        SituationalAwarenessDataAdapter(),  # no alert handler wired
        RecordingSink(runtime_store), state_store, runtime_store, _config(),
        clock=lambda: NOW,
    )

    first = connector.poll_once()
    assert first.disabled and first.error

    second = connector.poll_once()
    assert second.disabled
    assert second.fetched == 0  # the source is never queried again


def test_run_creation_failure_retries_then_abandons(runtime_store, state_store):
    alerts = [
        _alert("alert-1", detected_at=NOW - timedelta(minutes=3), digest="c" * 64),
        _alert("alert-2", detected_at=NOW - timedelta(minutes=2)),
    ]
    sink = RecordingSink(runtime_store, fail_records={"c" * 64})
    connector = _connector(
        lambda query: QueryPage(records=alerts), sink, state_store, runtime_store,
    )

    first = connector.poll_once()
    assert first.failed == ["siem/alert-1"]
    assert first.created_run_ids == ["run-001"]
    assert state_store.retryable_keys(TENANT) == {("siem", "alert-1")}

    connector.poll_once()  # failure 2
    third = connector.poll_once()  # failure 3 -> abandoned
    assert third.failed == ["siem/alert-1"]
    assert state_store.retryable_keys(TENANT) == set()
    events = [e for e in state_store.list_recent_events(TENANT)
              if e["kind"] == "intake_alert_skipped"]
    assert any(e["reason"] == "abandoned_after_retries" for e in events)
    fourth = connector.poll_once()
    assert fourth.failed == []  # abandoned alerts are no longer offered


def test_pagination_follows_the_cursor(runtime_store, state_store):
    pages = [
        QueryPage(records=[_alert("alert-1", detected_at=NOW - timedelta(minutes=2))],
                  next_cursor="page-2"),
        QueryPage(records=[_alert("alert-2", detected_at=NOW - timedelta(minutes=1))]),
    ]
    seen_cursors = []

    def handler(query):
        seen_cursors.append(query.cursor)
        return pages.pop(0)

    sink = RecordingSink(runtime_store)
    connector = _connector(handler, sink, state_store, runtime_store)

    report = connector.poll_once()
    assert report.fetched == 2
    assert sorted(report.created_run_ids) == ["run-001", "run-002"]
    assert seen_cursors == [None, "page-2"]


def test_mapper_converts_timestamps_and_optional_clues():
    detected = datetime(2026, 10, 15, 8, 30, tzinfo=timezone.utc)
    payload, reason = map_alert_to_payload(_alert("x", detected_at=detected))
    assert reason is None
    assert payload["discovery_time"] == payload["Recent_time"]
    assert payload["discovery_time"] == int(detected.timestamp() * 1000)

    container = _alert("y", detected_at=detected)
    container = container.model_copy(update={"container_id": "ctr-9"})
    payload, _ = map_alert_to_payload(container)
    assert payload["Container_id"] == "ctr-9"


def test_poll_endpoint_reports_and_lists_events(runtime_store, state_store):
    connector = _connector(
        lambda query: QueryPage(
            records=[_alert("alert-1", detected_at=NOW - timedelta(minutes=1))]
        ),
        RecordingSink(runtime_store), state_store, runtime_store,
    )
    app = create_app(None, alert_intake=connector)
    client = TestClient(app)

    response = client.post("/api/intake/poll")
    assert response.status_code == 200
    body = response.json()
    assert body["report"]["created_run_ids"] == ["run-001"]
    kinds = [event["kind"] for event in body["events"]]
    assert "intake_polled" in kinds and "intake_alert_accepted" not in kinds

    unconfigured = create_app(None)
    assert client_post(unconfigured, "/api/intake/poll") == 503


def client_post(app, path) -> int:
    with TestClient(app) as client:
        return client.post(path).status_code
