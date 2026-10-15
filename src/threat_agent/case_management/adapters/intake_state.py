from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

AlertKey = tuple[str, str]
# Alerts in these states must not be offered for processing again; "failed"
# stays retryable until the connector abandons it.
_TERMINAL_STATES = ("seen", "skipped", "abandoned")


class SQLiteIntakeStateStore:
    """Dedup keys, poll watermark and intake events for the alert connector."""

    def __init__(self, path: Path | str):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path), check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock, self.connection:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS intake_alerts (
                    tenant_id TEXT NOT NULL, source_system TEXT NOT NULL,
                    source_record_id TEXT NOT NULL, state TEXT NOT NULL,
                    reason TEXT, run_id TEXT, fail_count INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL, last_attempt TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, source_system, source_record_id)
                );
                CREATE TABLE IF NOT EXISTS intake_watermark (
                    tenant_id TEXT PRIMARY KEY,
                    watermark_epoch REAL NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS intake_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL, kind TEXT NOT NULL,
                    ref TEXT NOT NULL, reason TEXT,
                    recorded_at TEXT NOT NULL
                );
                """
            )

    def known_keys(self, tenant_id: str, keys: list[AlertKey]) -> set[AlertKey]:
        """Keys already recorded in a non-retryable state."""
        terminal = {
            (row["source_system"], row["source_record_id"])
            for row in self._select_alerts(tenant_id)
            if row["state"] in _TERMINAL_STATES
        }
        return {key for key in keys if key in terminal}

    def retryable_keys(self, tenant_id: str) -> set[AlertKey]:
        """Keys currently marked failed and waiting for another attempt."""
        return {
            (row["source_system"], row["source_record_id"])
            for row in self._select_alerts(tenant_id)
            if row["state"] == "failed"
        }

    def record_alert(
        self,
        tenant_id: str,
        key: AlertKey,
        *,
        state: str,
        run_id: str | None = None,
        reason: str | None = None,
        fail_count: int = 0,
    ) -> None:
        now = _now_text()
        with self._lock, self.connection:
            self.connection.execute(
                """
                INSERT INTO intake_alerts
                    (tenant_id, source_system, source_record_id, state, reason,
                     run_id, fail_count, first_seen, last_attempt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, source_system, source_record_id) DO UPDATE SET
                    state=excluded.state, reason=excluded.reason,
                    run_id=excluded.run_id, fail_count=excluded.fail_count,
                    last_attempt=excluded.last_attempt
                """,
                (tenant_id, key[0], key[1], state, reason, run_id, fail_count, now, now),
            )

    def get_fail_count(self, tenant_id: str, key: AlertKey) -> int:
        with self._lock:
            row = self.connection.execute(
                "SELECT fail_count FROM intake_alerts WHERE tenant_id=? AND source_system=? AND source_record_id=?",
                (tenant_id, key[0], key[1]),
            ).fetchone()
        return int(row["fail_count"]) if row else 0

    def get_watermark(self, tenant_id: str) -> datetime | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT watermark_epoch FROM intake_watermark WHERE tenant_id=?", (tenant_id,)
            ).fetchone()
        if row is None:
            return None
        return datetime.fromtimestamp(row["watermark_epoch"], tz=timezone.utc)

    def set_watermark(self, tenant_id: str, value: datetime) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                """
                INSERT INTO intake_watermark (tenant_id, watermark_epoch, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    watermark_epoch=excluded.watermark_epoch, updated_at=excluded.updated_at
                """,
                (tenant_id, value.timestamp(), _now_text()),
            )

    def append_event(self, tenant_id: str, kind: str, ref: str, reason: str | None = None) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT INTO intake_events (tenant_id, kind, ref, reason, recorded_at) VALUES (?, ?, ?, ?, ?)",
                (tenant_id, kind, ref, reason, _now_text()),
            )

    def list_recent_events(self, tenant_id: str, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT kind, ref, reason, recorded_at FROM intake_events "
                "WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def close(self) -> None:
        with self._lock:
            self.connection.close()

    def _select_alerts(self, tenant_id: str) -> list[sqlite3.Row]:
        with self._lock:
            return self.connection.execute(
                "SELECT source_system, source_record_id, state, run_id, fail_count "
                "FROM intake_alerts WHERE tenant_id=?",
                (tenant_id,),
            ).fetchall()


def _now_text() -> str:
    return datetime.now(timezone.utc).isoformat()
