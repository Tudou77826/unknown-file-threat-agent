"""Security data access ports and local development adapters."""

from .ports.evidence_query import DataAccessError
from .adapters.reference_store import SQLiteReferenceDataStore
from .adapters.activity_store import SQLiteActivityStore
from .adapters.parsers import ReferenceEventParser, VendorEnvelopeParser
from .application.ingestion import BatchIngestionService
from .ports.ingestion import ActivityIngestionStore, SourceParser
from .adapters.activity_query import SQLiteActivityQueryAdapter
from .domain.entity_projection import DeterministicEntityProjector, EntityProjection
from .ports.activity_query import (
    AssetActivityQueryPort, ExtensionActivityQueryPort, FileActivityQueryPort,
    NetworkActivityQueryPort, PackageActivityQueryPort, ProcessActivityQueryPort,
    ServiceActivityQueryPort, SocketActivityQueryPort,
)

__all__ = [
    "DataAccessError",
    "SQLiteReferenceDataStore",
    "ActivityIngestionStore",
    "BatchIngestionService",
    "ReferenceEventParser",
    "SourceParser",
    "SQLiteActivityStore",
    "VendorEnvelopeParser",
    "SQLiteActivityQueryAdapter",
    "DeterministicEntityProjector",
    "EntityProjection",
    "ProcessActivityQueryPort", "NetworkActivityQueryPort", "SocketActivityQueryPort",
    "FileActivityQueryPort", "ServiceActivityQueryPort", "PackageActivityQueryPort",
    "AssetActivityQueryPort", "ExtensionActivityQueryPort",
]
