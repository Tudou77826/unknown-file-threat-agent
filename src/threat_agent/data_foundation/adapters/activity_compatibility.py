from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from ...contracts import (
    AssetActivityQuery,
    Coverage,
    Evidence,
    EvidenceBundle,
    EvidenceQuery,
    EvidenceStatus,
    ExtensionActivityQuery,
    FileActivityQuery,
    NetworkActivityQuery,
    PackageActivityQuery,
    ProcessActivityQuery,
    ServiceActivityQuery,
    SocketActivityQuery,
)
from ..ports.evidence_query import DataAccessError
from .activity_query import SQLiteActivityQueryAdapter


_KNOWN_ACTIVITY_TYPES = {
    "process_exec": "process",
    "child_process_exec": "process",
    "process_parent_relation": "process",
    "network_connection": "network",
    "socket_io": "socket",
    "systemd_event": "service",
    "package_provenance": "package",
    "approved_endpoint": "asset",
}


class ActivityEvidenceQueryAdapter:
    """Offline-test projection from activity queries to deterministic analyzers.

    Coverage exists only because deterministic analyzer tests consume EvidenceBundle.
    This adapter is not part of the online LLM investigation path or a version-compatibility API.
    """

    def __init__(
        self,
        activity_queries: SQLiteActivityQueryAdapter,
        *,
        run_id: str = "offline-test-run",
        test_coverage_by_domain: dict[str, Coverage] | None = None,
    ):
        self.activity_queries = activity_queries
        self.run_id = run_id
        self.test_coverage_by_domain = test_coverage_by_domain or {}

    def query_evidence(self, query: EvidenceQuery) -> EvidenceBundle:
        if query.domain not in query.scope.allowed_domains:
            raise DataAccessError(f"Domain {query.domain!r} is outside the authorized scope")
        host = str(query.parameters.get("host_id") or "")
        hosts = [host] if host else list(query.scope.host_ids)
        entities = [str(item) for item in query.parameters.get("entity_ids") or []]
        start = self._datetime(query.parameters.get("start_time"))
        end = self._datetime(query.parameters.get("end_time"))
        grouped: dict[str, list[str]] = {}
        for event_type in query.evidence_types:
            grouped.setdefault(_KNOWN_ACTIVITY_TYPES.get(event_type, "extension"), []).append(event_type)

        evidence: list[Evidence] = []
        for activity_type, event_types in grouped.items():
            typed = self._typed_query(
                activity_type, query, event_types, hosts, entities, start, end,
                limit=max(1, query.limit - len(evidence)),
            )
            result = getattr(self.activity_queries, f"query_{activity_type}")(typed)
            for activity in result.activities:
                event_type = str(activity.extension.get("source_event_type") or event_types[0])
                data = activity.extension.get("source_data")
                if not isinstance(data, dict):
                    data = activity.model_dump(mode="json")
                raw_reference = activity.raw_record_ref
                if not raw_reference.startswith(("raw-record://", "reference-jsonl://")):
                    raw_reference = f"raw-record://{raw_reference}"
                evidence.append(Evidence(
                    evidence_id=activity.activity_id,
                    evidence_type=event_type,
                    domain=query.domain,
                    source_system=activity.source_system,
                    observed_at=activity.observed_at,
                    subject_refs=list(activity.extension.get("source_subject_refs") or activity.subject_refs),
                    data=data,
                    raw_reference=raw_reference,
                ))
                if len(evidence) >= query.limit:
                    break
            if len(evidence) >= query.limit:
                break
        evidence.sort(key=lambda item: (item.observed_at, item.evidence_id))
        status = EvidenceStatus.AVAILABLE if evidence else EvidenceStatus.EMPTY
        coverage = self.test_coverage_by_domain.get(query.domain) or Coverage(
            domain=query.domain,
            status=status,
            completeness="unknown",
            requested_start=start or query.scope.start_time,
            requested_end=end or query.scope.end_time,
            result_start=evidence[0].observed_at if evidence else None,
            result_end=evidence[-1].observed_at if evidence else None,
            limitations=["Offline deterministic-test projection; no data quality assessment"],
        )
        return EvidenceBundle(
            status=status,
            evidence=evidence,
            coverage=coverage,
            limitations=["Offline deterministic-test projection; online reasoning uses ActivityQueryResult"],
        )

    def _typed_query(self, activity_type, query, event_types, hosts, entities, start, end, limit):
        common: dict[str, Any] = {
            "tenant_id": query.tenant_id,
            "case_id": query.case_id,
            "source_identity": "activity-evidence-test-projection",
            "run_id": self.run_id,
            "query_id": f"{query.query_id}-{activity_type}",
            "scope": query.scope,
            "host_refs": hosts,
            "entity_refs": entities,
            "start_time": start,
            "end_time": end,
            "source_event_types": event_types,
            "limit": limit,
        }
        classes = {
            "process": ProcessActivityQuery,
            "network": NetworkActivityQuery,
            "socket": SocketActivityQuery,
            "file": FileActivityQuery,
            "service": ServiceActivityQuery,
            "package": PackageActivityQuery,
            "asset": AssetActivityQuery,
            "extension": ExtensionActivityQuery,
        }
        return classes[activity_type](**common)

    @staticmethod
    def _datetime(value: Any) -> datetime | None:
        if value in (None, ""):
            return None
        if isinstance(value, datetime):
            return value
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
