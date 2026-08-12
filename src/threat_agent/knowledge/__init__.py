"""RAG integration contracts without a retrieval implementation."""

from .adapters.null_retriever import NullKnowledgeRetriever
from .ports.retrieval import KnowledgeRetrievalPort

__all__ = ["KnowledgeRetrievalPort", "NullKnowledgeRetriever"]
