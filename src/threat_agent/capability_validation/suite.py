"""Suite manifest and repository: version pinning over git-stored cases.

Storage decision (Step 01): cases live in git next to the code; binaries go
to ``replay/artifacts/`` with a per-artifact size cap (default 10 MiB —
technique selection already prefers small ELF payloads). Object storage is a
later migration; the directory convention keeps cases portable.

Version pinning follows the agent_eval convention ``case@suite_version``:
the manifest records a content digest per case, computed over every file
under the case directory, so a pinned suite version always reproduces the
exact bytes that were scored.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import Field

from ._base import StrictModel
from .case_model import TestCase
from .replay import ReplayBundle

MAX_ARTIFACT_BYTES = 10 * 1024 * 1024


class CaseEntry(StrictModel):
    case_id: str = Field(min_length=1)
    directory: str = Field(min_length=1)
    content_digest: str | None = Field(
        default=None, description="sha256 over all case files; set by ``refresh``"
    )


class SuiteManifest(StrictModel):
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    created: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    storage: dict[str, object] = Field(default_factory=dict)
    cases: list[CaseEntry] = Field(min_length=1)


class LoadedCase:
    def __init__(self, bundle: ReplayBundle, suite_version: str) -> None:
        self.bundle = bundle
        self.case: TestCase = bundle.case
        # agent_eval-style pinned reference.
        self.case_ref = f"{bundle.case.case_id}@{suite_version}"


class ValidationSuiteRepository:
    """Loads and verifies a ``validation_cases/`` tree."""

    def __init__(self, root: Path, max_artifact_bytes: int = MAX_ARTIFACT_BYTES) -> None:
        self.root = root
        self.max_artifact_bytes = max_artifact_bytes

    @property
    def manifest_path(self) -> Path:
        return self.root / "manifest.json"

    def load_manifest(self) -> SuiteManifest:
        return SuiteManifest.model_validate(
            json.loads(self.manifest_path.read_text(encoding="utf-8"))
        )

    def load(self, *, verify_digests: bool = True) -> tuple[SuiteManifest, list[LoadedCase]]:
        manifest = self.load_manifest()
        loaded: list[LoadedCase] = []
        for entry in manifest.cases:
            case_dir = (self.root / entry.directory).resolve()
            if not case_dir.is_dir():
                raise ValueError(f"case directory missing: {case_dir}")
            self._enforce_artifact_limit(case_dir)
            digest = digest_case_directory(case_dir)
            if (
                verify_digests
                and entry.content_digest
                and entry.content_digest != digest
            ):
                raise ValueError(
                    f"content digest mismatch for {entry.case_id}: pinned "
                    f"{entry.content_digest} vs actual {digest} — refresh the manifest "
                    f"only through reviewed case changes"
                )
            bundle = ReplayBundle.load(case_dir)
            if bundle.case.case_id != entry.case_id:
                raise ValueError(
                    f"manifest/case id mismatch: {entry.case_id} vs {bundle.case.case_id}"
                )
            loaded.append(LoadedCase(bundle, manifest.suite_version))
        return manifest, loaded

    def refresh_digests(self) -> SuiteManifest:
        """Recompute and persist content digests after a reviewed case change."""

        manifest = self.load_manifest()
        for entry in manifest.cases:
            entry.content_digest = digest_case_directory((self.root / entry.directory).resolve())
        self.manifest_path.write_text(
            json.dumps(manifest.model_dump(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return manifest

    def _enforce_artifact_limit(self, case_dir: Path) -> None:
        artifacts = case_dir / "replay" / "artifacts"
        if not artifacts.is_dir():
            return
        for path in artifacts.rglob("*"):
            if path.is_file() and path.stat().st_size > self.max_artifact_bytes:
                raise ValueError(
                    f"artifact exceeds {self.max_artifact_bytes} bytes: {path}"
                )


def digest_case_directory(case_dir: Path) -> str:
    """Deterministic digest: file list sorted by relative path + contents."""

    hasher = hashlib.sha256()
    files = sorted(
        path for path in case_dir.rglob("*") if path.is_file() and ".git" not in path.parts
    )
    for path in files:
        relative = path.relative_to(case_dir).as_posix()
        hasher.update(relative.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()
