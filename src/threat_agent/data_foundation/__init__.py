"""Security data access ports and local development adapters."""

from .adapters.repository import EvidenceRepository, FixtureEvidenceRepository, JsonlEventRepository
from .adapters.repository_query import RepositoryEvidenceQueryAdapter
from .ports.evidence_query import DataAccessError, EvidenceQueryPort
from .adapters.reference_store import SQLiteEvidenceQueryAdapter, SQLiteReferenceDataStore
from .adapters.activity_store import SQLiteActivityStore
from .adapters.parsers import ReferenceEventParser, VendorEnvelopeParser
from .application.ingestion import BatchIngestionService
from .ports.ingestion import ActivityIngestionStore, SourceParser
from .adapters.activity_query import SQLiteActivityQueryAdapter
from .adapters.activity_compatibility import ActivityEvidenceQueryAdapter
from .domain.entity_projection import DeterministicEntityProjector, EntityProjection
from .ports.activity_query import (
    AssetActivityQueryPort, ExtensionActivityQueryPort, FileActivityQueryPort,
    NetworkActivityQueryPort, PackageActivityQueryPort, ProcessActivityQueryPort,
    ServiceActivityQueryPort, SocketActivityQueryPort,
)

__all__ = [
    "DataAccessError",
    "EvidenceQueryPort",
    "EvidenceRepository",
    "FixtureEvidenceRepository",
    "JsonlEventRepository",
    "RepositoryEvidenceQueryAdapter",
    "SQLiteEvidenceQueryAdapter",
    "SQLiteReferenceDataStore",
    "ActivityIngestionStore",
    "BatchIngestionService",
    "ReferenceEventParser",
    "SourceParser",
    "SQLiteActivityStore",
    "VendorEnvelopeParser",
    "SQLiteActivityQueryAdapter",
    "ActivityEvidenceQueryAdapter",
    "DeterministicEntityProjector",
    "EntityProjection",
    "ProcessActivityQueryPort", "NetworkActivityQueryPort", "SocketActivityQueryPort",
    "FileActivityQueryPort", "ServiceActivityQueryPort", "PackageActivityQueryPort",
    "AssetActivityQueryPort", "ExtensionActivityQueryPort",
]
