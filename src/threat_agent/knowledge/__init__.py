"""RAG integration: capability layer (business scenario services) over the
supplier-shaped adapter port. Agent-side modules import only the capability
service from here; adapters and ports stay implementation details."""

from .adapters.null_supplier import NullKnowledgeSupplier
from .adapters.reference_retriever import ReferenceKnowledgeAdapter
from .application.capability import (
    SecurityKnowledgeService,
    UnsupportedKnowledgeRequestError,
)
from .ports.supplier_retrieval import SupplierRetrievalPort

__all__ = [
    "NullKnowledgeSupplier",
    "ReferenceKnowledgeAdapter",
    "SecurityKnowledgeService",
    "SupplierRetrievalPort",
    "UnsupportedKnowledgeRequestError",
]
