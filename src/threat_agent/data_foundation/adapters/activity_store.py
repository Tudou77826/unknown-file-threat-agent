from __future__ import annotations


class _LockedConnection:
    """sqlite3 connection proxy that serializes execute* across threads.

    create_agent executes tool calls on worker threads that share one
    connection; interleaved parameter binding produced intermittent
    sqlite3.InterfaceError("bad parameter or other API misuse")."""

    def __init__(self, connection):
        import threading

        self._connection = connection
        self._lock = threading.RLock()

    def execute(self, sql, params=()):
        with self._lock:
            return self._connection.execute(sql, params)

    def executemany(self, sql, seq):
        with self._lock:
            return self._connection.executemany(sql, seq)

    def executescript(self, script):
        with self._lock:
            return self._connection.executescript(script)

    def commit(self):
        with self._lock:
            return self._connection.commit()

    def close(self):
        with self._lock:
            return self._connection.close()

    def __enter__(self):
        self._lock.acquire()
        return self._connection.__enter__()

    def __exit__(self, *args):
        try:
            return self._connection.__exit__(*args)
        finally:
            self._lock.release()

    def __setattr__(self, name, value):
        if name in ("_connection", "_lock"):
            object.__setattr__(self, name, value)
        else:
            setattr(self._connection, name, value)

    def __getattr__(self, name):
        return getattr(self._connection, name)


import json
import sqlite3
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from ...contracts import (
    DatasetManifest, EntityIdentity, IngestionReport, NormalizedActivity,
    ObservedRelation, RawRecordEnvelope,
)
from ..domain.entity_projection import DeterministicEntityProjector


_ACTIVITY_ADAPTER = TypeAdapter(NormalizedActivity)


class SQLiteActivityStore:
    """Local storage adapter for raw records and normalized activities."""

    def __init__(self, path: Path | str, *, check_same_thread: bool = True):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Agent runtimes built on create_agent execute tools on worker
        # threads; sequential cross-thread use requires check_same_thread=False.
        self.connection = _LockedConnection(
            sqlite3.connect(str(self.path), check_same_thread=check_same_thread)
        )
        self.connection.row_factory = sqlite3.Row
        self.entity_projector = DeterministicEntityProjector()
        self.initialize()

    def initialize(self) -> None:
        self.connection.executescript(
            """
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS ingestion_batches (
                tenant_id TEXT NOT NULL,
                dataset_id TEXT NOT NULL,
                dataset_version TEXT NOT NULL,
                batch_id TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, dataset_id, dataset_version, batch_id)
            );
            CREATE TABLE IF NOT EXISTS raw_records (
                tenant_id TEXT NOT NULL,
                raw_record_id TEXT NOT NULL,
                source_system TEXT NOT NULL,
                source_record_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, raw_record_id),
                UNIQUE (tenant_id, source_system, source_record_id)
            );
            CREATE TABLE IF NOT EXISTS normalized_activities (
                tenant_id TEXT NOT NULL,
                activity_id TEXT NOT NULL,
                activity_type TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                source_system TEXT NOT NULL,
                source_record_id TEXT NOT NULL,
                host_ref TEXT,
                subject_refs_json TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, activity_id),
                FOREIGN KEY (tenant_id, source_system, source_record_id)
                    REFERENCES raw_records(tenant_id, source_system, source_record_id)
            );
            CREATE TABLE IF NOT EXISTS quarantined_records (
                tenant_id TEXT NOT NULL,
                dataset_id TEXT NOT NULL,
                dataset_version TEXT NOT NULL,
                batch_id TEXT NOT NULL,
                source_record_id TEXT NOT NULL,
                error_type TEXT NOT NULL,
                message TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, dataset_id, dataset_version, batch_id, source_record_id)
            );
            CREATE TABLE IF NOT EXISTS entity_identities (
                tenant_id TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, entity_id)
            );
            CREATE TABLE IF NOT EXISTS observed_relations (
                tenant_id TEXT NOT NULL,
                relation_id TEXT NOT NULL,
                relation_type TEXT NOT NULL,
                source_entity_ref TEXT NOT NULL,
                target_entity_ref TEXT NOT NULL,
                resolution_status TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, relation_id)
            );
            CREATE INDEX IF NOT EXISTS idx_activity_tenant_type_time
                ON normalized_activities(tenant_id, activity_type, observed_at);
            CREATE INDEX IF NOT EXISTS idx_activity_tenant_host_time
                ON normalized_activities(tenant_id, host_ref, observed_at);
            CREATE INDEX IF NOT EXISTS idx_activity_tenant_source_record
                ON normalized_activities(tenant_id, source_system, source_record_id);
            CREATE INDEX IF NOT EXISTS idx_entity_tenant_type
                ON entity_identities(tenant_id, entity_type);
            CREATE INDEX IF NOT EXISTS idx_relation_tenant_source
                ON observed_relations(tenant_id, source_entity_ref, relation_type);
            CREATE INDEX IF NOT EXISTS idx_relation_tenant_target
                ON observed_relations(tenant_id, target_entity_ref, relation_type);
            """
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def begin_batch(self, manifest: DatasetManifest) -> None:
        self.connection.execute(
            "INSERT OR IGNORE INTO ingestion_batches VALUES (?, ?, ?, ?, ?)",
            (
                manifest.tenant_id,
                manifest.dataset_id,
                manifest.dataset_version,
                manifest.batch_id,
                manifest.model_dump_json(),
            ),
        )
        self.connection.commit()

    def raw_record_exists(self, tenant_id: str, source_system: str, source_record_id: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM raw_records WHERE tenant_id=? AND source_system=? AND source_record_id=?",
            (tenant_id, source_system, source_record_id),
        ).fetchone()
        return row is not None

    def raw_record_digest(
        self, tenant_id: str, source_system: str, source_record_id: str
    ) -> str | None:
        row = self.connection.execute(
            "SELECT payload_digest FROM raw_records WHERE tenant_id=? AND source_system=? AND source_record_id=?",
            (tenant_id, source_system, source_record_id),
        ).fetchone()
        return str(row["payload_digest"]) if row else None

    def put_record_with_activities(
        self,
        manifest: DatasetManifest,
        record: RawRecordEnvelope,
        payload: dict[str, Any],
        activities: list[NormalizedActivity],
    ) -> None:
        if record.tenant_id != manifest.tenant_id:
            raise ValueError("record does not match ingestion manifest")
        with self.connection:
            self.connection.execute(
                "INSERT INTO raw_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.tenant_id,
                    record.raw_record_id,
                    record.source_system,
                    record.source_record_id,
                    record.observed_at.isoformat(),
                    record.ingested_at.isoformat(),
                    record.payload_digest,
                    record.model_dump_json(),
                    json.dumps(payload, ensure_ascii=False, sort_keys=True),
                ),
            )
            for activity in activities:
                if activity.tenant_id != record.tenant_id:
                    raise ValueError("activity tenant does not match raw record")
                if activity.source_system != record.source_system:
                    raise ValueError("activity source does not match raw record")
                if activity.source_record_id != record.source_record_id:
                    raise ValueError("activity source record does not match raw record")
                host_ref = getattr(activity, "host_ref", None)
                self.connection.execute(
                    "INSERT INTO normalized_activities VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        activity.tenant_id,
                        activity.activity_id,
                        activity.activity_type,
                        activity.observed_at.isoformat(),
                        activity.source_system,
                        activity.source_record_id,
                        host_ref,
                        json.dumps(activity.subject_refs, ensure_ascii=False),
                        activity.model_dump_json(),
                    ),
                )
                projection = self.entity_projector.project(activity)
                for identity in projection.entities:
                    self.put_entity(identity)
                for relation in projection.relations:
                    self.put_relation(relation)

    def put_entity(self, identity: EntityIdentity) -> None:
        existing_row = self.connection.execute(
            "SELECT payload_json FROM entity_identities WHERE tenant_id=? AND entity_id=?",
            (identity.tenant_id, identity.entity_id),
        ).fetchone()
        if existing_row:
            existing = EntityIdentity.model_validate_json(existing_row["payload_json"])
            aliases = {(item.source_system, item.source_id, item.valid_from, item.valid_to): item for item in existing.aliases}
            aliases.update({(item.source_system, item.source_id, item.valid_from, item.valid_to): item for item in identity.aliases})
            identity = identity.model_copy(update={
                "aliases": list(aliases.values()),
                "attributes": {**existing.attributes, **identity.attributes},
                "resolution_confidence": max(existing.resolution_confidence, identity.resolution_confidence),
                "valid_from": existing.valid_from or identity.valid_from,
                "valid_to": identity.valid_to or existing.valid_to,
            })
        self.connection.execute(
            "INSERT OR REPLACE INTO entity_identities VALUES (?, ?, ?, ?)",
            (identity.tenant_id, identity.entity_id, identity.entity_type, identity.model_dump_json()),
        )

    def put_relation(self, relation: ObservedRelation) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO observed_relations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                relation.tenant_id, relation.relation_id, relation.relation_type,
                relation.source_entity_ref, relation.target_entity_ref,
                relation.resolution_status,
                (relation.valid_from or relation.created_at).isoformat(),
                relation.model_dump_json(),
            ),
        )

    def quarantine_record(
        self,
        manifest: DatasetManifest,
        source_record_id: str,
        payload: dict[str, Any],
        error_type: str,
        message: str,
    ) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO quarantined_records VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                manifest.tenant_id,
                manifest.dataset_id,
                manifest.dataset_version,
                manifest.batch_id,
                source_record_id,
                error_type,
                message,
                json.dumps(payload, ensure_ascii=False, sort_keys=True),
            ),
        )
        self.connection.commit()

    def finalize_batch(self, manifest: DatasetManifest, report: IngestionReport) -> None:
        # The ingestion report stores observed counts, domains, times, and failures.
        # The data layer does not turn those facts into a quality or coverage grade.
        return None

    def count_raw_records(self, tenant_id: str) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) AS count FROM raw_records WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        return int(row["count"])

    def count_activities(self, tenant_id: str) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) AS count FROM normalized_activities WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        return int(row["count"])

    def count_quarantined(self, tenant_id: str, batch_id: str) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) AS count FROM quarantined_records WHERE tenant_id=? AND batch_id=?",
            (tenant_id, batch_id),
        ).fetchone()
        return int(row["count"])

    def list_activities(self, tenant_id: str) -> list[NormalizedActivity]:
        rows = self.connection.execute(
            "SELECT payload_json FROM normalized_activities WHERE tenant_id=? ORDER BY observed_at, activity_id",
            (tenant_id,),
        ).fetchall()
        return [_ACTIVITY_ADAPTER.validate_json(row["payload_json"]) for row in rows]

    def list_entities(self, tenant_id: str) -> list[EntityIdentity]:
        rows = self.connection.execute(
            "SELECT payload_json FROM entity_identities WHERE tenant_id=? ORDER BY entity_id",
            (tenant_id,),
        ).fetchall()
        return [EntityIdentity.model_validate_json(row["payload_json"]) for row in rows]

    def list_relations(self, tenant_id: str) -> list[ObservedRelation]:
        rows = self.connection.execute(
            "SELECT payload_json FROM observed_relations WHERE tenant_id=? ORDER BY relation_id",
            (tenant_id,),
        ).fetchall()
        return [ObservedRelation.model_validate_json(row["payload_json"]) for row in rows]

    def get_entity(self, tenant_id: str, entity_id: str) -> EntityIdentity | None:
        row = self.connection.execute(
            "SELECT payload_json FROM entity_identities WHERE tenant_id=? AND entity_id=?",
            (tenant_id, entity_id),
        ).fetchone()
        return EntityIdentity.model_validate_json(row["payload_json"]) if row else None

    def get_activity(self, tenant_id: str, activity_id: str) -> NormalizedActivity | None:
        row = self.connection.execute(
            "SELECT payload_json FROM normalized_activities WHERE tenant_id=? AND activity_id=?",
            (tenant_id, activity_id),
        ).fetchone()
        return _ACTIVITY_ADAPTER.validate_json(row["payload_json"]) if row else None

    def get_raw_payload(self, tenant_id: str, raw_record_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT payload_json FROM raw_records WHERE tenant_id=? AND raw_record_id=?",
            (tenant_id, raw_record_id),
        ).fetchone()
        return json.loads(row["payload_json"]) if row else None

    def find_relations(
        self, tenant_id: str, entity_id: str, direction: str = "both"
    ) -> list[ObservedRelation]:
        clauses = []
        args: list[str] = [tenant_id]
        if direction in {"outbound", "both"}:
            clauses.append("source_entity_ref=?")
            args.append(entity_id)
        if direction in {"inbound", "both"}:
            clauses.append("target_entity_ref=?")
            args.append(entity_id)
        rows = self.connection.execute(
            "SELECT payload_json FROM observed_relations WHERE tenant_id=? AND ("
            + " OR ".join(clauses)
            + ") ORDER BY observed_at, relation_id",
            args,
        ).fetchall()
        return [ObservedRelation.model_validate_json(row["payload_json"]) for row in rows]
