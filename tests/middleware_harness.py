"""Shared fixtures for canonical framework-middleware runtime tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel

from threat_agent.contracts import DatasetManifest
from threat_agent.data_foundation import (
    BatchIngestionService,
    ReferenceEventParser,
    SQLiteActivityStore,
)


TENANT = "tenant-a"
RUN = "run-a"


class ScriptedModel(GenericFakeChatModel):
    """Scripted model that accepts (and ignores) tool binding."""

    def bind_tools(self, tools, **kwargs):
        return self


def seed_store(tmp_path: Path) -> SQLiteActivityStore:
    """Two hosts in one tenant sharing one external endpoint."""

    store = SQLiteActivityStore(tmp_path / "activities.sqlite", check_same_thread=False)
    parser = ReferenceEventParser()
    manifest = DatasetManifest(
        tenant_id=TENANT,
        dataset_id="dataset",
        dataset_version="1",
        batch_id="batch",
        source_system="reference",
        connector_version="1",
        parser_name=parser.name,
        parser_version=parser.version,
    )
    events = [
        {
            "event_id": "p1",
            "event_type": "process_exec",
            "domain": "process",
            "source_system": "edr-process",
            "observed_at": "2026-04-23T03:20:44Z",
            "host_id": "host-1",
            "subject_refs": ["process:host-1:10:1776914444000"],
            "data": {
                "process_ref": "process:host-1:10:1776914444000",
                "executable": "/tmp/a",
            },
        },
        {
            "event_id": "n1",
            "event_type": "network_connection",
            "domain": "network",
            "source_system": "edr-network",
            "observed_at": "2026-04-23T03:21:44Z",
            "host_id": "host-1",
            "subject_refs": [
                "process:host-1:10:1776914444000",
                "endpoint:203.0.113.5:443",
            ],
            "data": {
                "process_ref": "process:host-1:10:1776914444000",
                "protocol": "tcp",
            },
        },
        {
            "event_id": "p2",
            "event_type": "process_exec",
            "domain": "process",
            "source_system": "edr-process",
            "observed_at": "2026-04-23T03:22:44Z",
            "host_id": "host-2",
            "subject_refs": ["process:host-2:20:1776914456000"],
            "data": {
                "process_ref": "process:host-2:20:1776914456000",
                "executable": "/tmp/b",
            },
        },
    ]
    BatchIngestionService(store, parser).ingest_payloads(
        manifest,
        events,
        ingested_at=datetime(2026, 8, 12, tzinfo=timezone.utc),
    )
    return store
