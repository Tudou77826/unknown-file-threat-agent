from __future__ import annotations

import json
from pathlib import Path

from ...contracts import DataProfile, DatasetManifest, ReferenceAsset, ReferenceDatasetMetadata
from ..adapters.activity_store import SQLiteActivityStore
from ..adapters.parsers import ReferenceEventParser
from ..adapters.reference_store import SQLiteReferenceDataStore
from .ingestion import BatchIngestionService


def reference_activity_store_path(reference_path: Path, dataset_id: str) -> Path:
    return reference_path.with_name(f"{reference_path.stem}-{dataset_id}-activities.sqlite")


def _import_activity_dataset(
    reference_store: SQLiteReferenceDataStore,
    *,
    dataset_id: str,
    dataset_version: str,
    case_dir: Path,
) -> None:
    activity_store = SQLiteActivityStore(reference_activity_store_path(reference_store.path, dataset_id))
    parser = ReferenceEventParser()
    try:
        payloads = []
        for path in sorted((case_dir / "events").glob("*.jsonl")):
            payloads.extend(
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
        BatchIngestionService(activity_store, parser).ingest_payloads(
            DatasetManifest(
                tenant_id="default",
                source_identity="reference-demo-initializer",
                dataset_id=dataset_id,
                dataset_version=dataset_version,
                batch_id=f"{dataset_id}-{dataset_version}",
                source_system="reference-demo",
                connector_version="reference-demo/1.0",
                parser_name=parser.name,
                parser_version=parser.version,
                expected_record_count=len(payloads),
            ),
            payloads,
        )
    finally:
        activity_store.close()


def initialize_reference_demo(
    store: SQLiteReferenceDataStore,
    *,
    project_root: Path,
    demo_data_root: Path | None = None,
) -> dict[str, ReferenceDatasetMetadata]:
    """Import versioned, non-production demo assets into the reference store."""

    root = (demo_data_root or project_root / "demo_data").resolve()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    version = str(manifest["dataset_version"])
    seed = int(manifest["random_seed"])
    results: dict[str, ReferenceDatasetMetadata] = {}
    for item in manifest["datasets"]:
        dataset_id = str(item["dataset_id"])
        case_dir = (project_root / item["case_directory"]).resolve()
        metadata = store.import_case_directory(
            case_dir,
            dataset_id=dataset_id,
            dataset_version=version,
            label=str(item["label"]),
            random_seed=seed,
        )
        for profile_path in item["profiles"]:
            profile = DataProfile.model_validate_json(
                (root / profile_path).read_text(encoding="utf-8")
            )
            store.put_profile(dataset_id, version, profile)
        results[dataset_id] = metadata
        _import_activity_dataset(
            store,
            dataset_id=dataset_id,
            dataset_version=version,
            case_dir=case_dir,
        )
    for raw_asset in manifest.get("assets", []):
        asset = ReferenceAsset.model_validate(raw_asset["asset"])
        store.put_asset(str(raw_asset["dataset_id"]), version, asset)
    return results
