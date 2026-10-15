"""Automatic intake of unknown-file alerts from the situational-awareness port.

The connector is a consumer of ``query_alerts``: it polls a time window,
maps source alerts onto the intake payload ``initialize_state`` reads, and
creates runs through the same entry the workbench manual intake uses. It never
touches the source database or IR directly.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from ...contracts import AlertQuery, AuditEvent, QueryPage, Scope, UnknownFileAlert
from ...data_foundation import DataAccessError, DataQueryFailed, UnsupportedDataQuery
from ...shared.model import StrictModel
from ..adapters.intake_state import AlertKey, SQLiteIntakeStateStore
from .intake import derive_case_id

RETRY_LIMIT = 3


class AlertSourcePort(Protocol):
    def query_alerts(self, query: AlertQuery) -> QueryPage[UnknownFileAlert]: ...


class AlertIntakeSink(Protocol):
    def start_alert(self, raw_alert: dict[str, Any]) -> str: ...


class AlertIntakeAuditStore(Protocol):
    def next_audit_sequence(self, tenant_id: str, run_id: str) -> int: ...

    def append_audit_event(self, event: AuditEvent) -> None: ...


@dataclass(frozen=True)
class AlertIntakeConfig:
    tenant_id: str
    host_ids: tuple[str, ...]
    interval_seconds: int = 300
    max_runs_per_poll: int = 5
    alert_limit: int = 50
    page_limit: int = 20


class IntakePollReport(StrictModel):
    window_start: datetime | None = None
    window_end: datetime
    fetched: int = 0
    pending: int = 0
    created_run_ids: list[str] = []
    skipped: list[str] = []
    failed: list[str] = []
    watermark: datetime | None = None
    disabled: bool = False
    error: str | None = None


def map_alert_to_payload(alert: UnknownFileAlert) -> tuple[dict[str, Any] | None, str | None]:
    """Map a source alert onto the intake payload; None payload carries the skip reason.

    ``initialize_state`` anchors a case on sha256 + path + host; alerts without
    those cannot become runs and are skipped explicitly rather than dropped.
    """
    if alert.file_hash is None or alert.file_hash.algorithm != "sha256":
        return None, "skipped_unsupported_hash"
    if not alert.file_path:
        return None, "skipped_missing_field"
    payload: dict[str, Any] = {
        "File_hash": alert.file_hash.digest,
        "File_path": alert.file_path,
        "Sub_asset": alert.host_ref,
        "source": alert.source_system,
    }
    if alert.detected_at is not None:
        millis = int(alert.detected_at.timestamp() * 1000)
        payload["discovery_time"] = millis
        payload["Recent_time"] = millis
    if alert.pid is not None or alert.process_name:
        payload["Detail"] = {"context": [{"pid": alert.pid, "path": alert.process_name}]}
    if alert.container_id:
        payload["Container_id"] = alert.container_id
    return payload, None


class AlertIntakeConnector:
    """One poll cycle: query window, dedup, create runs, advance watermark.

    Watermark semantics: it advances only to the latest ``detected_at`` among
    alerts successfully processed this round, never to the wall clock. Alerts
    beyond the per-round cap or awaiting retry stay inside the window (which
    reaches 2x interval below the watermark), so no alert is lost to paging.
    """

    def __init__(
        self,
        source: AlertSourcePort,
        sink: AlertIntakeSink,
        state: SQLiteIntakeStateStore,
        audit_store: AlertIntakeAuditStore,
        config: AlertIntakeConfig,
        *,
        clock: Callable[[], datetime] | None = None,
    ):
        self.source = source
        self.sink = sink
        self.state = state
        self.audit_store = audit_store
        self.config = config
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        self._disabled = False

    def close(self) -> None:
        self.state.close()

    def recent_events(self, limit: int = 20) -> list[dict]:
        return self.state.list_recent_events(self.config.tenant_id, limit)

    def poll_once(self) -> IntakePollReport:
        if self._disabled:
            return IntakePollReport(
                window_end=self._clock(), disabled=True,
                error="source does not support alert queries; connector disabled",
            )
        if not self._lock.acquire(blocking=False):
            return IntakePollReport(window_end=self._clock(), error="poll already in progress")
        try:
            return self._poll_locked()
        finally:
            self._lock.release()

    # ------------------------------------------------------------------ cycle

    def _poll_locked(self) -> IntakePollReport:
        now = self._clock()
        tenant = self.config.tenant_id
        watermark = self.state.get_watermark(tenant)
        tolerance = timedelta(seconds=2 * self.config.interval_seconds)
        window_start = (watermark or now) - tolerance

        try:
            alerts = self._fetch_alerts(window_start, now)
        except UnsupportedDataQuery as error:
            self._disabled = True
            self.state.append_event(tenant, "intake_poll_failed", "-", f"unsupported: {error}")
            return IntakePollReport(
                window_start=window_start, window_end=now, disabled=True,
                error=f"source does not support alert queries: {error}",
            )
        except DataAccessError as error:
            # Failed or out-of-scope reads keep the watermark; the next round retries.
            self.state.append_event(tenant, "intake_poll_failed", "-", str(error))
            return IntakePollReport(
                window_start=window_start, window_end=now,
                watermark=watermark, error=f"source query failed: {error}",
            )

        keyed = {(alert.source_system, alert.source_record_id): alert for alert in alerts}
        known = self.state.known_keys(tenant, list(keyed))
        pending = sorted(
            (alert for key, alert in keyed.items() if key not in known),
            key=lambda alert: alert.detected_at or datetime.min.replace(tzinfo=timezone.utc),
        )

        created: list[str] = []
        skipped: list[str] = []
        failed: list[str] = []
        latest_success: datetime | None = None
        for alert in pending[: self.config.max_runs_per_poll]:
            key = (alert.source_system, alert.source_record_id)
            ref = f"{alert.source_system}/{alert.source_record_id}"
            payload, skip_reason = map_alert_to_payload(alert)
            if payload is None:
                self.state.record_alert(tenant, key, state="skipped", reason=skip_reason)
                self.state.append_event(tenant, "intake_alert_skipped", ref, skip_reason)
                skipped.append(ref)
                continue
            try:
                run_id = self.sink.start_alert(payload)
            except Exception as error:
                fail_count = self.state.get_fail_count(tenant, key) + 1
                if fail_count >= RETRY_LIMIT:
                    self.state.record_alert(
                        tenant, key, state="abandoned",
                        reason="abandoned_after_retries", fail_count=fail_count,
                    )
                    self.state.append_event(
                        tenant, "intake_alert_skipped", ref, "abandoned_after_retries"
                    )
                else:
                    self.state.record_alert(
                        tenant, key, state="failed",
                        reason=f"{type(error).__name__}: {error}", fail_count=fail_count,
                    )
                    self.state.append_event(tenant, "intake_alert_failed", ref, str(error))
                failed.append(ref)
                continue
            self.state.record_alert(tenant, key, state="seen", run_id=run_id)
            self._audit_accepted(alert, payload, run_id)
            created.append(run_id)
            if alert.detected_at is not None and (
                latest_success is None or alert.detected_at > latest_success
            ):
                latest_success = alert.detected_at

        if latest_success is not None and latest_success != watermark:
            self.state.set_watermark(tenant, latest_success)
        self.state.append_event(
            tenant, "intake_polled", "-",
            f"fetched={len(alerts)} pending={len(pending)} created={len(created)} "
            f"skipped={len(skipped)} failed={len(failed)}",
        )
        return IntakePollReport(
            window_start=window_start, window_end=now,
            fetched=len(alerts), pending=len(pending),
            created_run_ids=created, skipped=skipped, failed=failed,
            watermark=latest_success or watermark,
        )

    def _fetch_alerts(self, window_start: datetime, now: datetime) -> list[UnknownFileAlert]:
        query = AlertQuery(
            tenant_id=self.config.tenant_id,
            scope=Scope(
                host_ids=list(self.config.host_ids),
                start_time=window_start, end_time=now,
            ),
            limit=self.config.alert_limit,
        )
        alerts: list[UnknownFileAlert] = []
        for _ in range(self.config.page_limit):
            page = self.source.query_alerts(query)
            alerts.extend(page.records)
            if page.next_cursor is None:
                return alerts
            query = query.model_copy(update={"cursor": page.next_cursor})
        # Page cap reached: process what was fetched; the window tolerance keeps
        # the tail visible next round instead of silently dropping it.
        return alerts

    def _audit_accepted(
        self, alert: UnknownFileAlert, payload: dict[str, Any], run_id: str
    ) -> None:
        sequence = self.audit_store.next_audit_sequence(self.config.tenant_id, run_id)
        self.audit_store.append_audit_event(
            AuditEvent(
                tenant_id=self.config.tenant_id,
                case_id=derive_case_id(payload),
                source_identity="alert-intake",
                run_id=run_id,
                audit_id=f"audit-{run_id}-{sequence:05d}",
                sequence=sequence,
                action="intake_alert_accepted",
                resource_type="source_alert",
                resource_ref=f"{alert.source_system}/{alert.source_record_id}",
                input_refs=[alert.raw_reference] if alert.raw_reference else [],
                result_summary=f"态势感知告警自动接入，创建运行 {run_id}",
                correlation_id=run_id,
            )
        )


class AlertIntakePoller:
    """Background polling loop for serve mode; failures never kill the thread."""

    def __init__(self, connector: AlertIntakeConnector, interval_seconds: int):
        self._connector = connector
        self._interval = max(1, int(interval_seconds))
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="alert-intake-poller", daemon=True
        )

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._connector.poll_once()
            except Exception:
                continue

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
