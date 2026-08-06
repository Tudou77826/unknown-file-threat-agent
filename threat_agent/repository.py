from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Protocol

from .models import Coverage, Evidence, EvidenceBundle, EvidenceStatus, InvestigationState


class EvidenceRepository(Protocol):
    def query(
        self,
        domain: str,
        evidence_types: frozenset[str],
        state: InvestigationState,
        parameters: dict[str, Any] | None = None,
    ) -> EvidenceBundle: ...


def _datetime(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _strings(item)


def _field(data: dict[str, Any], dotted_name: str) -> Any:
    current: Any = data
    for part in dotted_name.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


class FixtureEvidenceRepository:
    """Case-scoped repository with real query filtering over normalized fixtures.

    P1.2 keeps compatibility with evidence.json. P1.3 will feed the same query
    contract from raw JSONL event adapters.
    """

    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        path = case_dir / "evidence.json"
        raw_records = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
        self.records = [Evidence.model_validate(row) for row in raw_records]
        coverage_path = case_dir / "coverage.json"
        self.coverage_config = json.loads(coverage_path.read_text(encoding="utf-8")) if coverage_path.exists() else {}

    def query(
        self,
        domain: str,
        evidence_types: frozenset[str],
        state: InvestigationState,
        parameters: dict[str, Any] | None = None,
    ) -> EvidenceBundle:
        parameters = parameters or {}
        config = self.coverage_config.get(domain, {})
        configured_status = EvidenceStatus(config.get("status", "available"))
        limitations = list(config.get("limitations", []))
        requested_start = _datetime(parameters.get("start_time")) or state.scope.start_time
        requested_end = _datetime(parameters.get("end_time")) or state.scope.end_time

        candidates = [
            row for row in self.records
            if row.domain == domain and row.evidence_type in evidence_types
        ]
        observed = sorted(row.observed_at for row in candidates if row.observed_at is not None)
        completeness = config.get("completeness")
        if completeness is None:
            completeness = {
                EvidenceStatus.AVAILABLE: "complete",
                EvidenceStatus.PARTIAL: "partial",
                EvidenceStatus.UNAVAILABLE: "unavailable",
                EvidenceStatus.ERROR: "unavailable",
            }.get(configured_status, "unknown")
        coverage = Coverage(
            domain=domain,
            status=configured_status,
            host_id=str(parameters.get("host_id") or (state.scope.host_ids[0] if len(state.scope.host_ids) == 1 else "")) or None,
            source_system=str(config.get("source_system")) if config.get("source_system") else None,
            completeness=completeness,
            requested_start=requested_start,
            requested_end=requested_end,
            available_start=_datetime(config.get("available_start")) or (requested_start if completeness == "complete" else None),
            available_end=_datetime(config.get("available_end")) or (requested_end if completeness == "complete" else None),
            result_start=observed[0] if observed else None,
            result_end=observed[-1] if observed else None,
            limitations=limitations,
        )
        if configured_status in {EvidenceStatus.UNAVAILABLE, EvidenceStatus.ERROR, EvidenceStatus.EMPTY}:
            return EvidenceBundle(status=configured_status, coverage=coverage, limitations=limitations)

        requested_host = str(parameters.get("host_id") or (state.scope.host_ids[0] if len(state.scope.host_ids) == 1 else ""))
        entity_ids = set(parameters.get("entity_ids") or [])
        filters = parameters.get("filters") or {}
        limit = int(parameters.get("limit", 1000))

        rows = []
        for row in candidates:
            values = set(row.subject_refs) | set(_strings(row.data))
            # Records without an explicit host anchor are accepted because the
            # repository itself is already scoped to one case. Anchored records
            # must match the requested host.
            anchored_hosts = {
                part.split(":", 2)[1]
                for part in values
                if part.startswith(("host:", "file:", "process:", "user:", "container:")) and part.count(":") >= 2
            }
            explicit_host = row.data.get("host_id")
            if explicit_host:
                anchored_hosts.add(str(explicit_host))
            if requested_host and anchored_hosts and requested_host not in anchored_hosts:
                continue
            if entity_ids and not (entity_ids & values):
                continue
            if requested_start and row.observed_at and row.observed_at < requested_start:
                continue
            if requested_end and row.observed_at and row.observed_at > requested_end:
                continue
            if any(
                (_field(row.data, key) not in expected if isinstance(expected, list) else _field(row.data, key) != expected)
                for key, expected in filters.items()
            ):
                continue
            rows.append(row)

        rows.sort(key=lambda item: (item.observed_at is None, item.observed_at, item.evidence_id))
        if len(rows) > limit:
            rows = rows[:limit]
            limitations.append(f"Result truncated to requested limit {limit}")
            coverage.limitations = limitations
        if not rows:
            return EvidenceBundle(status=EvidenceStatus.EMPTY, evidence=[], coverage=coverage, limitations=limitations)
        status = EvidenceStatus.PARTIAL if configured_status == EvidenceStatus.PARTIAL or limitations else EvidenceStatus.AVAILABLE
        return EvidenceBundle(status=status, evidence=rows, coverage=coverage, limitations=limitations)


class JsonlEventRepository(FixtureEvidenceRepository):
    """Load raw case events from events/*.jsonl and normalize them at query time."""

    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.records: list[Evidence] = []
        events_dir = case_dir / "events"
        for path in sorted(events_dir.glob("*.jsonl")):
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if not line.strip():
                    continue
                event = json.loads(line)
                data = dict(event.get("data") or {})
                if event.get("host_id"):
                    data.setdefault("host_id", event["host_id"])
                self.records.append(Evidence(
                    evidence_id=str(event["event_id"]),
                    evidence_type=str(event["event_type"]),
                    domain=str(event["domain"]),
                    source_system=str(event.get("source_system", path.stem)),
                    observed_at=_datetime(event.get("observed_at")),
                    subject_refs=[str(item) for item in event.get("subject_refs", [])],
                    data=data,
                    status=EvidenceStatus(event.get("status", "available")),
                    limitations=[str(item) for item in event.get("limitations", [])],
                    raw_reference=f"jsonl://{path.name}:{line_number}",
                ))
        coverage_path = case_dir / "coverage.json"
        self.coverage_config = json.loads(coverage_path.read_text(encoding="utf-8")) if coverage_path.exists() else {}
