from __future__ import annotations

import json
from pathlib import Path

from ...contracts import DataProfile, ReferenceAsset, ReferenceDatasetMetadata
from ..adapters.reference_store import SQLiteReferenceDataStore


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
        metadata = store.import_case_directory(
            (project_root / item["case_directory"]).resolve(),
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
    for raw_asset in manifest.get("assets", []):
        asset = ReferenceAsset.model_validate(raw_asset["asset"])
        store.put_asset(str(raw_asset["dataset_id"]), version, asset)
    return results
