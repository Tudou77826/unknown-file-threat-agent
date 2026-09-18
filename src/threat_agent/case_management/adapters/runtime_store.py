from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from ...contracts import AuditEvent, InvestigationRun, OperationalEvent


class SQLiteInvestigationRuntimeStore:
    """Persistent run facts, operational events, audit records and published artifacts."""

    def __init__(self, path: Path | str):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path), check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self.initialize()

    def initialize(self) -> None:
        with self._lock, self.connection:
            self.connection.executescript(
                """
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS investigation_runs (
                    tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, case_id TEXT NOT NULL,
                    dataset_id TEXT NOT NULL, profile_id TEXT NOT NULL,
                    status TEXT NOT NULL, stage TEXT NOT NULL, payload_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, run_id)
                );
                CREATE TABLE IF NOT EXISTS operational_events (
                    tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL, event_type TEXT NOT NULL, stage TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, run_id, sequence), UNIQUE (tenant_id, event_id),
                    FOREIGN KEY (tenant_id, run_id) REFERENCES investigation_runs(tenant_id, run_id)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                    audit_id TEXT NOT NULL, action TEXT NOT NULL, resource_type TEXT NOT NULL,
                    resource_ref TEXT NOT NULL, payload_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, run_id, sequence), UNIQUE (tenant_id, audit_id),
                    FOREIGN KEY (tenant_id, run_id) REFERENCES investigation_runs(tenant_id, run_id)
                );
                CREATE TABLE IF NOT EXISTS run_artifacts (
                    tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, artifact_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL, PRIMARY KEY (tenant_id, run_id, artifact_type),
                    FOREIGN KEY (tenant_id, run_id) REFERENCES investigation_runs(tenant_id, run_id)
                );
                CREATE INDEX IF NOT EXISTS idx_runtime_status ON investigation_runs(tenant_id, status, stage);
                CREATE INDEX IF NOT EXISTS idx_operational_event_type ON operational_events(tenant_id, run_id, event_type, sequence);
                CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(tenant_id, run_id, action, sequence);
                """
            )

    def close(self) -> None:
        with self._lock:
            self.connection.close()

    def create_run(self, run: InvestigationRun, *, dataset_id: str, profile_id: str) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT INTO investigation_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (run.tenant_id, run.run_id, run.case_id, dataset_id, profile_id,
                 run.status, run.stage, run.model_dump_json()),
            )

    def get_run(self, tenant_id: str, run_id: str) -> InvestigationRun | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT payload_json FROM investigation_runs WHERE tenant_id=? AND run_id=?",
                (tenant_id, run_id),
            ).fetchone()
        return InvestigationRun.model_validate_json(row["payload_json"]) if row else None

    def get_run_metadata(self, tenant_id: str, run_id: str) -> dict[str, str] | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT dataset_id, profile_id FROM investigation_runs WHERE tenant_id=? AND run_id=?",
                (tenant_id, run_id),
            ).fetchone()
        return dict(row) if row else None

    def update_run(self, run: InvestigationRun) -> None:
        with self._lock, self.connection:
            changed = self.connection.execute(
                "UPDATE investigation_runs SET status=?, stage=?, payload_json=? WHERE tenant_id=? AND run_id=?",
                (run.status, run.stage, run.model_dump_json(), run.tenant_id, run.run_id),
            ).rowcount
            if changed != 1:
                raise KeyError(f"Unknown investigation run: {run.tenant_id}/{run.run_id}")

    def list_runs(self, tenant_id: str) -> list[tuple[InvestigationRun, str, str]]:
        """Newest-first run rows with their source metadata (dataset, profile)."""

        with self._lock:
            rows = self.connection.execute(
                "SELECT payload_json, dataset_id, profile_id FROM investigation_runs "
                "WHERE tenant_id=? ORDER BY rowid DESC",
                (tenant_id,),
            ).fetchall()
        return [
            (
                InvestigationRun.model_validate_json(row["payload_json"]),
                str(row["dataset_id"]),
                str(row["profile_id"]),
            )
            for row in rows
        ]

    def next_operational_sequence(self, tenant_id: str, run_id: str) -> int:
        with self._lock:
            row = self.connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 value FROM operational_events WHERE tenant_id=? AND run_id=?",
                (tenant_id, run_id),
            ).fetchone()
        return int(row["value"])

    def next_audit_sequence(self, tenant_id: str, run_id: str) -> int:
        with self._lock:
            row = self.connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 value FROM audit_events WHERE tenant_id=? AND run_id=?",
                (tenant_id, run_id),
            ).fetchone()
        return int(row["value"])

    def append_operational_event(self, event: OperationalEvent) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT INTO operational_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                (event.tenant_id, event.run_id, event.sequence, event.event_id,
                 event.event_type, event.stage, event.model_dump_json()),
            )

    def append_audit_event(self, event: AuditEvent) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (event.tenant_id, event.run_id, event.sequence, event.audit_id, event.action,
                 event.resource_type, event.resource_ref, event.model_dump_json()),
            )

    def list_operational_events(self, tenant_id: str, run_id: str) -> list[OperationalEvent]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT payload_json FROM operational_events WHERE tenant_id=? AND run_id=? ORDER BY sequence",
                (tenant_id, run_id),
            ).fetchall()
        return [OperationalEvent.model_validate_json(row["payload_json"]) for row in rows]

    def list_audit_events(self, tenant_id: str, run_id: str) -> list[AuditEvent]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT payload_json FROM audit_events WHERE tenant_id=? AND run_id=? ORDER BY sequence",
                (tenant_id, run_id),
            ).fetchall()
        return [AuditEvent.model_validate_json(row["payload_json"]) for row in rows]

    def list_audit_global(
        self, tenant_id: str, *, action: str | None = None, limit: int = 300
    ) -> list[AuditEvent]:
        """Newest-first audit trail across every run of the tenant."""

        with self._lock:
            if action:
                rows = self.connection.execute(
                    "SELECT payload_json FROM audit_events WHERE tenant_id=? AND action=? "
                    "ORDER BY rowid DESC LIMIT ?",
                    (tenant_id, action, limit),
                ).fetchall()
            else:
                rows = self.connection.execute(
                    "SELECT payload_json FROM audit_events WHERE tenant_id=? "
                    "ORDER BY rowid DESC LIMIT ?",
                    (tenant_id, limit),
                ).fetchall()
        return [AuditEvent.model_validate_json(row["payload_json"]) for row in rows]

    def put_artifact(self, tenant_id: str, run_id: str, artifact_type: str, payload: dict[str, Any]) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO run_artifacts VALUES (?, ?, ?, ?)",
                (tenant_id, run_id, artifact_type, json.dumps(payload, ensure_ascii=False)),
            )

    def get_artifact(self, tenant_id: str, run_id: str, artifact_type: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT payload_json FROM run_artifacts WHERE tenant_id=? AND run_id=? AND artifact_type=?",
                (tenant_id, run_id, artifact_type),
            ).fetchone()
        return json.loads(row["payload_json"]) if row else None
