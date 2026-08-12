from __future__ import annotations

from typing import Literal

from pydantic import Field

from ..shared import StrictModel
from .common import ContractModel


class KnowledgeQuery(ContractModel):
    query_id: str = Field(min_length=1)
    knowledge_domain: Literal["investigation", "response", "case_memory"]
    query_text: str = Field(min_length=1)
    acl_tags: list[str] = Field(default_factory=list)


class KnowledgeCitation(StrictModel):
    document_id: str
    document_version: str
    chunk_id: str
    title: str
    source_uri: str
    content: str


class KnowledgeResult(ContractModel):
    query_id: str = Field(min_length=1)
    status: Literal["available", "empty", "not_configured", "error"]
    citations: list[KnowledgeCitation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
