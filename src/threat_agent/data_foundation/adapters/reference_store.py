from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from ...contracts import (
    Coverage,
    DataProfile,
    Evidence,
    EvidenceBundle,
    EvidenceQuery,
    EvidenceStatus,
    ReferenceAsset,
    ReferenceDatasetMetadata,
)
from ..ports.evidence_query import DataAccessError


SCHEMA_VERSION = "1"


def _json(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _strings(item)


class SQLiteReferenceDataStore:
    """Local reference-data implementation; not a production data lake."""

    def __init__(self, path: Path | str):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path))
        self.connection.row_factory = sqlite3.Row
        self.initialize()

    def initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS datasets (
                dataset_id TEXT NOT NULL,
                dataset_version TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                PRIMARY KEY (dataset_id, dataset_version)
            );
            CREATE TABLE IF NOT EXISTS cases (
                dataset_id TEXT NOT NULL,
                dataset_version TEXT NOT NULL,
                case_id TEXT NOT NULL,
                input_json TEXT NOT NULL,
                PRIMARY KEY (dataset_id, dataset_version, case_id)
            );
            CREATE TABLE IF NOT EXISTS evidence (
                dataset_id TEXT NOT NULL,
                dataset_version TEXT NOT NULL,
                case_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                source_system TEXT NOT NULL,
                observed_at TEXT,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (dataset_id, dataset_version, case_id, evidence_id)
            );
            CREATE TABLE IF NOT EXISTS coverage (
                dataset_id TEXT NOT NULL,
                dataset_version TEXT NOT NULL,
                case_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                source_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (dataset_id, dataset_version, case_id, domain, source_id)
            );
            CREATE TABLE IF NOT EXISTS entities (
                dataset_id TEXT NOT NULL,
                dataset_version TEXT NOT NULL,
                case_id TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (dataset_id, dataset_version, case_id, entity_id)
            );
            CREATE TABLE IF NOT EXISTS relations (
                dataset_id TEXT NOT NULL,
                dataset_version TEXT NOT NULL,
                case_id TEXT NOT NULL,
                relation_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (dataset_id, dataset_version, case_id, relation_id)
            );
            CREATE TABLE IF NOT EXISTS assets (
                dataset_id TEXT NOT NULL,
                dataset_version TEXT NOT NULL,
                host_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (dataset_id, dataset_version, host_id)
            );
            CREATE TABLE IF NOT EXISTS profiles (
                dataset_id TEXT NOT NULL,
                dataset_version TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (dataset_id, dataset_version, profile_id)
            );
            """
        )
        existing = self.connection.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        if existing is not None and existing["value"] != SCHEMA_VERSION:
            raise RuntimeError(
                f"Unsupported reference store schema {existing['value']}; expected {SCHEMA_VERSION}"
            )
        self.connection.execute(
            "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', ?)",
            (SCHEMA_VERSION,),
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def put_dataset(self, metadata: ReferenceDatasetMetadata) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO datasets VALUES (?, ?, ?)",
            (metadata.dataset_id, metadata.dataset_version, _json(metadata)),
        )
        self.connection.commit()

    def put_case(self, dataset_id: str, dataset_version: str, case_id: str, raw: dict) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO cases VALUES (?, ?, ?, ?)",
            (dataset_id, dataset_version, case_id, _json(raw)),
        )
        self.connection.commit()

    def put_evidence(
        self, dataset_id: str, dataset_version: str, case_id: str, evidence: Evidence
    ) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                dataset_id,
                dataset_version,
                case_id,
                evidence.evidence_id,
                evidence.domain,
                evidence.evidence_type,
                evidence.source_system,
                evidence.observed_at.isoformat() if evidence.observed_at else None,
                _json(evidence),
            ),
        )

    def put_coverage(
        self,
        dataset_id: str,
        dataset_version: str,
        case_id: str,
        source_id: str,
        coverage: Coverage,
    ) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO coverage VALUES (?, ?, ?, ?, ?, ?)",
            (dataset_id, dataset_version, case_id, coverage.domain, source_id, _json(coverage)),
        )

    def put_asset(
        self, dataset_id: str, dataset_version: str, asset: ReferenceAsset
    ) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO assets VALUES (?, ?, ?, ?)",
            (dataset_id, dataset_version, asset.host_id, _json(asset)),
        )
        self.connection.commit()

    def put_profile(
        self, dataset_id: str, dataset_version: str, profile: DataProfile
    ) -> None:
        if profile.dataset_version != dataset_version:
            raise ValueError("Profile dataset_version does not match target dataset")
        self.connection.execute(
            "INSERT OR REPLACE INTO profiles VALUES (?, ?, ?, ?)",
            (dataset_id, dataset_version, profile.profile_id, _json(profile)),
        )
        self.connection.commit()

    def get_profile(
        self, dataset_id: str, dataset_version: str, profile_id: str
    ) -> DataProfile:
        row = self.connection.execute(
            "SELECT payload_json FROM profiles WHERE dataset_id=? AND dataset_version=? AND profile_id=?",
            (dataset_id, dataset_version, profile_id),
        ).fetchone()
        if row is None:
            raise KeyError(f"Unknown data profile: {dataset_id}/{dataset_version}/{profile_id}")
        return DataProfile.model_validate_json(row["payload_json"])

    def list_profiles(self, dataset_id: str, dataset_version: str) -> list[DataProfile]:
        rows = self.connection.execute(
            "SELECT payload_json FROM profiles WHERE dataset_id=? AND dataset_version=?",
            (dataset_id, dataset_version),
        ).fetchall()
        order = {"l0": 0, "l1": 1, "l2": 2, "l3": 3}
        return sorted(
            (DataProfile.model_validate_json(row["payload_json"]) for row in rows),
            key=lambda item: (order[item.level], item.profile_id),
        )

    def get_case_input(
        self, dataset_id: str, dataset_version: str, case_id: str
    ) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT input_json FROM cases WHERE dataset_id=? AND dataset_version=? AND case_id=?",
            (dataset_id, dataset_version, case_id),
        ).fetchone()
        if row is None:
            raise KeyError(f"Unknown reference case: {dataset_id}/{dataset_version}/{case_id}")
        return json.loads(row["input_json"])

    def get_dataset(
        self, dataset_id: str, dataset_version: str
    ) -> ReferenceDatasetMetadata:
        row = self.connection.execute(
            "SELECT metadata_json FROM datasets WHERE dataset_id=? AND dataset_version=?",
            (dataset_id, dataset_version),
        ).fetchone()
        if row is None:
            raise KeyError(f"Unknown reference dataset: {dataset_id}/{dataset_version}")
        return ReferenceDatasetMetadata.model_validate_json(row["metadata_json"])

    def get_asset(
        self, dataset_id: str, dataset_version: str, host_id: str
    ) -> ReferenceAsset | None:
        row = self.connection.execute(
            "SELECT payload_json FROM assets WHERE dataset_id=? AND dataset_version=? AND host_id=?",
            (dataset_id, dataset_version, host_id),
        ).fetchone()
        return ReferenceAsset.model_validate_json(row["payload_json"]) if row else None

    def import_case_directory(
        self,
        case_dir: Path,
        *,
        dataset_id: str,
        dataset_version: str,
        label: str,
        random_seed: int,
    ) -> ReferenceDatasetMetadata:
        input_path = case_dir / "input.json"
        raw = json.loads(input_path.read_text(encoding="utf-8"))
        case_id = "case-" + hashlib.sha256(
            str(raw.get("File_id") or raw.get("file_id") or case_dir.name).encode()
        ).hexdigest()[:12]
        source_bytes = input_path.read_bytes()
        records: list[Evidence] = []
        for path in sorted((case_dir / "events").glob("*.jsonl")):
            source_bytes += path.read_bytes()
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if not line.strip():
                    continue
                event = json.loads(line)
                data = dict(event.get("data") or {})
                if event.get("host_id"):
                    data.setdefault("host_id", event["host_id"])
                records.append(
                    Evidence(
                        evidence_id=str(event["event_id"]),
                        evidence_type=str(event["event_type"]),
                        domain=str(event["domain"]),
                        source_system=str(event.get("source_system", path.stem)),
                        observed_at=event.get("observed_at"),
                        subject_refs=[str(item) for item in event.get("subject_refs", [])],
                        data=data,
                        status=event.get("status", "available"),
                        limitations=[str(item) for item in event.get("limitations", [])],
                        raw_reference=f"reference-jsonl://{path.name}:{line_number}",
                    )
                )
        coverage_path = case_dir / "coverage.json"
        coverage_config = (
            json.loads(coverage_path.read_text(encoding="utf-8"))
            if coverage_path.exists()
            else {}
        )
        if coverage_path.exists():
            source_bytes += coverage_path.read_bytes()
        metadata = ReferenceDatasetMetadata(
            dataset_id=dataset_id,
            dataset_version=dataset_version,
            scenario="backdoor_c2",
            label=label,
            random_seed=random_seed,
            content_digest=hashlib.sha256(source_bytes).hexdigest(),
        )
        self.put_dataset(metadata)
        self.put_case(dataset_id, dataset_version, case_id, raw)
        for evidence in records:
            self.put_evidence(dataset_id, dataset_version, case_id, evidence)
        for domain, config in coverage_config.items():
            self.put_coverage(
                dataset_id,
                dataset_version,
                case_id,
                str(config.get("source_system") or domain),
                Coverage(
                    domain=domain,
                    status=config.get("status", "available"),
                    source_system=config.get("source_system"),
                    completeness=config.get("completeness", "unknown"),
                    available_start=config.get("available_start"),
                    available_end=config.get("available_end"),
                    limitations=config.get("limitations", []),
                ),
            )
        self.connection.commit()
        return metadata

    def count_evidence(self, dataset_id: str, dataset_version: str, case_id: str) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) count FROM evidence WHERE dataset_id=? AND dataset_version=? AND case_id=?",
            (dataset_id, dataset_version, case_id),
        ).fetchone()
        return int(row["count"])


class SQLiteEvidenceQueryAdapter:
    def __init__(
        self,
        store: SQLiteReferenceDataStore,
        *,
        dataset_id: str,
        dataset_version: str,
        visible_sources: set[str] | None = None,
        profile: DataProfile | None = None,
    ):
        self.store = store
        self.dataset_id = dataset_id
        self.dataset_version = dataset_version
        if profile is not None and profile.dataset_version != dataset_version:
            raise ValueError("Profile dataset_version does not match adapter dataset")
        self.profile = profile
        self.visible_sources = set(profile.visible_sources) if profile else visible_sources

    def query_evidence(self, query: EvidenceQuery) -> EvidenceBundle:
        if query.domain not in query.scope.allowed_domains:
            raise DataAccessError(f"Domain {query.domain!r} is outside the authorized scope")
        placeholders = ",".join("?" for _ in query.evidence_types)
        sql = (
            "SELECT payload_json FROM evidence WHERE dataset_id=? AND dataset_version=? "
            f"AND case_id=? AND domain=? AND evidence_type IN ({placeholders})"
        )
        args: list[Any] = [
            self.dataset_id,
            self.dataset_version,
            query.case_id,
            query.domain,
            *query.evidence_types,
        ]
        rows = self.store.connection.execute(sql, args).fetchall()
        evidence = [Evidence.model_validate_json(row["payload_json"]) for row in rows]
        if self.visible_sources is not None:
            evidence = [item for item in evidence if item.source_system in self.visible_sources]
        requested_host = str(query.parameters.get("host_id") or "")
        if requested_host and requested_host not in query.scope.host_ids:
            raise DataAccessError(f"Host {requested_host!r} is outside the authorized scope")
        start = query.scope.start_time
        end = query.scope.end_time
        filtered: list[Evidence] = []
        for item in evidence:
            values = set(item.subject_refs) | set(_strings(item.data))
            if requested_host and requested_host not in values and item.data.get("host_id") != requested_host:
                continue
            if start and item.observed_at and item.observed_at < start:
                continue
            if end and item.observed_at and item.observed_at > end:
                continue
            filtered.append(item)
        filtered.sort(key=lambda item: (item.observed_at is None, item.observed_at, item.evidence_id))
        filtered = filtered[: query.limit]
        coverage_rows = self.store.connection.execute(
            "SELECT source_id, payload_json FROM coverage WHERE dataset_id=? AND dataset_version=? AND case_id=? AND domain=?",
            (self.dataset_id, self.dataset_version, query.case_id, query.domain),
        ).fetchall()
        coverage_items = [
            (row["source_id"], Coverage.model_validate_json(row["payload_json"]))
            for row in coverage_rows
            if self.visible_sources is None or row["source_id"] in self.visible_sources
        ]
        profile_rules = (
            [rule for rule in self.profile.coverage_rules if query.domain in rule.domains]
            if self.profile
            else []
        )
        visible_rules = [
            rule for rule in profile_rules if rule.source_id in (self.visible_sources or set())
        ]
        if self.profile is not None:
            if visible_rules:
                completeness_order = {"complete": 3, "partial": 2, "unknown": 1, "unavailable": 0}
                best = max(visible_rules, key=lambda item: completeness_order[item.completeness])
                coverage = Coverage(
                    domain=query.domain,
                    status=best.status,
                    source_system=best.source_id,
                    completeness=best.completeness,
                    limitations=list(best.limitations),
                )
            else:
                coverage = Coverage(
                    domain=query.domain,
                    status=EvidenceStatus.UNAVAILABLE,
                    completeness="unavailable",
                    limitations=["The selected data profile does not expose this domain"],
                )
        else:
            coverage = coverage_items[0][1] if coverage_items else Coverage(
                domain=query.domain,
                status=EvidenceStatus.UNAVAILABLE,
                completeness="unavailable",
                limitations=["Reference dataset does not expose this data source"],
            )
        if not filtered and coverage.status == EvidenceStatus.AVAILABLE:
            status = EvidenceStatus.EMPTY
        else:
            status = coverage.status
        return EvidenceBundle(
            status=status,
            evidence=filtered,
            coverage=coverage,
            limitations=list(coverage.limitations),
        )
