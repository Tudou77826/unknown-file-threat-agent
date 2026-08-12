from __future__ import annotations

from typing import Protocol

from ...contracts import DataProfile, JudgmentResult, ReferenceAsset, ResponseContext


class ReferenceAssetLookup(Protocol):
    def get_asset(
        self, dataset_id: str, dataset_version: str, host_id: str
    ) -> ReferenceAsset | None: ...


def _host_ids(judgment: JudgmentResult) -> list[str]:
    hosts: list[str] = []
    refs = [
        ref
        for item in [*judgment.facts, *judgment.findings]
        for ref in item.subject_refs
    ]
    for ref in refs:
        parts = ref.split(":")
        if parts[0] == "host" and len(parts) > 1:
            hosts.append(parts[1])
        elif parts[0] in {"file", "process"} and len(parts) > 1:
            hosts.append(parts[1])
    return list(dict.fromkeys(hosts))


class ReferenceResponseContextAdapter:
    """Read asset and business constraints from the reference data foundation."""

    def __init__(
        self,
        store: ReferenceAssetLookup,
        *,
        dataset_id: str,
        dataset_version: str,
        profile: DataProfile,
    ):
        self.store = store
        self.dataset_id = dataset_id
        self.dataset_version = dataset_version
        self.profile = profile

    def load(self, judgment: JudgmentResult) -> ResponseContext:
        if not self.profile.asset_context_visible:
            return ResponseContext(
                tenant_id=judgment.tenant_id,
                case_id=judgment.case_id,
                source_identity="reference-data/asset-context",
                missing_context=["Asset and business context is hidden by the selected data profile"],
            )
        assets = []
        missing = []
        for host_id in _host_ids(judgment):
            asset = self.store.get_asset(self.dataset_id, self.dataset_version, host_id)
            if asset is None:
                missing.append(f"No reference asset context exists for host {host_id}")
            else:
                assets.append(asset.model_dump(mode="json"))
        if not assets:
            missing.append("No governed asset was resolved from the judgment subjects")
        return ResponseContext(
            tenant_id=judgment.tenant_id,
            case_id=judgment.case_id,
            source_identity="reference-data/asset-context",
            asset_context={"assets": assets},
            missing_context=list(dict.fromkeys(missing)),
        )
