"""Feature 19 Step 01 gates: loadable hand-written cases, variant derivation
with shared ground truth, projection contract, version pinning.

The pipeline test at the bottom is the real "可被完整加载" gate: a derived
variant flows through the existing data-foundation ingestion path
(the same one demo/reference cases use), proving the replay contract is
byte-compatible with the AI-side pipeline without the standalone package
importing it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from threat_agent.capability_validation import (
    DerivedCase,
    TestCase as TestCaseModel,
    ValidationSuiteRepository,
    derive_variant,
    digest_case_directory,
    materialize_default,
    validate_canonical_event,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SUITE_ROOT = PROJECT_ROOT / "validation_cases"


def _load_suite():
    manifest, loaded = ValidationSuiteRepository(SUITE_ROOT).load()
    return manifest, {item.case.case_id: item for item in loaded}


def test_suite_loads_handwritten_cases_completely():
    manifest, cases = _load_suite()
    assert manifest.suite_version == "2026.09.1"
    assert set(cases) == {"c2-malicious-elf", "c2-benign-baseline"}
    for case_id, item in cases.items():
        # Version-pinned reference, agent_eval convention.
        assert item.case_ref == f"{case_id}@{manifest.suite_version}"
        # Complete load = case + file record + canonical events + inventory.
        assert item.bundle.input_record["File_hash"] == item.case.judgment_target.file_hash
        assert item.bundle.events, f"{case_id} has no events"
        for event in item.bundle.events:
            validate_canonical_event(event)


def test_case_schema_requires_double_layer_ground_truth():
    minimal = json.loads(
        (SUITE_ROOT / "c2-benign-baseline" / "case.json").read_text(encoding="utf-8")
    )
    TestCaseModel.model_validate(minimal)  # complete case passes
    for drop in ("behavior", "file"):
        broken = json.loads(json.dumps(minimal))
        broken["ground_truth"].pop(drop)
        with pytest.raises(ValidationError):
            TestCaseModel.model_validate(broken)


def test_variant_shares_ground_truth_and_completes_fields():
    _, cases = _load_suite()
    item = cases["c2-malicious-elf"]
    (spec,) = item.case.parameters.variants
    result = derive_variant(item.bundle, spec)

    assert result.derived.case.case_id == "c2-malicious-elf~alt-endpoint"
    # Shared exam answer: ground truth copied verbatim, never re-authored.
    assert result.derived.case.ground_truth == item.case.ground_truth
    # Field completeness after substitution (strict model re-validated).
    assert result.derived.case.judgment_target.file_hash == item.bundle.input_record["File_hash"]
    endpoints = {
        event["data"]["remote_ip"]
        for event in result.derived.events
        if event["event_type"] == "network_connection"
    }
    assert endpoints == {"198.51.100.77"}
    # Default view reproduces the original replay bytes.
    default = materialize_default(item.bundle)
    assert isinstance(default, DerivedCase)
    default_endpoints = {
        event["data"]["remote_ip"]
        for event in default.events
        if event["event_type"] == "network_connection"
    }
    assert default_endpoints == {"203.0.113.50"}


def test_derivation_rejects_unknown_parameters():
    _, cases = _load_suite()
    item = cases["c2-malicious-elf"]
    from threat_agent.capability_validation import VariantSpec

    with pytest.raises(ValueError, match="unknown parameters"):
        derive_variant(
            item.bundle,
            VariantSpec(variant_id="bad", parameters={"nope": "x"}),
        )


def test_canonical_event_contract_rejects_malformed_events():
    good = {
        "event_id": "e1",
        "event_type": "process_exec",
        "domain": "process",
        "observed_at": "2026-04-23T03:20:44Z",
        "host_id": "server-01",
        "subject_refs": [],
        "data": {},
    }
    validate_canonical_event(good)
    with pytest.raises(ValueError, match="missing keys"):
        validate_canonical_event({key: value for key, value in good.items() if key != "host_id"})
    with pytest.raises(ValueError, match="subject_refs"):
        validate_canonical_event({**good, "subject_refs": "process:server-01:1:1"})


def test_content_digest_pins_case_bytes(tmp_path: Path):
    repo_dir = tmp_path / "suite"
    repo_dir.mkdir()
    for name in ("manifest.json",):
        (repo_dir / name).write_text(
            (SUITE_ROOT / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
    for case_name in ("c2-malicious-elf", "c2-benign-baseline"):
        shutil_copytree(SUITE_ROOT / case_name, repo_dir / case_name)
    repo = ValidationSuiteRepository(repo_dir)
    repo.refresh_digests()
    repo.load()  # pinned digests verify

    tampered = repo_dir / "c2-benign-baseline" / "replay" / "events" / "network.jsonl"
    tampered.write_text(
        tampered.read_text(encoding="utf-8") + "\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="content digest mismatch"):
        repo.load()
    assert digest_case_directory(SUITE_ROOT / "c2-benign-baseline") != "x" * 64


def test_artifact_size_limit(tmp_path: Path):
    case_dir = tmp_path / "case"
    (case_dir / "replay" / "artifacts").mkdir(parents=True)
    (case_dir / "replay" / "artifacts" / "huge.bin").write_bytes(b"\0" * (10 * 1024 * 1024 + 1))
    repo = ValidationSuiteRepository(tmp_path)
    with pytest.raises(ValueError, match="exceeds"):
        repo._enforce_artifact_limit(case_dir)


def test_raw_telemetry_kind_is_probe_scoped():
    from threat_agent.capability_validation import RawTelemetryEnvelope

    RawTelemetryEnvelope(
        kind="process", collector="auditd/1", captured_at="t", host_id="h", payload={}
    )
    with pytest.raises(ValidationError, match="telemetry kind"):
        RawTelemetryEnvelope(
            kind="made_up", collector="x/1", captured_at="t", host_id="h", payload={}
        )


def test_ground_truth_must_be_literal(tmp_path: Path):
    payload = json.loads(
        (SUITE_ROOT / "c2-malicious-elf" / "case.json").read_text(encoding="utf-8")
    )
    # A *declared* parameter name in GT is the dangerous case: it survives
    # the shared-truth restore as a literal {{...}} instead of erroring.
    payload["ground_truth"]["file"]["basis"] = "端点 {{c2_endpoint}} 不在批准清单"
    suite = tmp_path / "suite"
    suite.mkdir()
    shutil_copytree(SUITE_ROOT / "c2-malicious-elf", suite / "c2-malicious-elf")
    (suite / "c2-malicious-elf" / "case.json").write_text(
        json.dumps(payload, ensure_ascii=False), encoding="utf-8"
    )
    manifest = json.loads((SUITE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["cases"]:
        entry["content_digest"] = None  # case.json was rewritten; unpin for this probe
    (suite / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="ground truth must be literal"):
        ValidationSuiteRepository(suite).load()


def test_manifest_rejects_duplicate_case_references():
    from threat_agent.capability_validation import SuiteManifest

    entry = {"case_id": "a", "directory": "d"}
    with pytest.raises(ValidationError, match="duplicate case"):
        SuiteManifest.model_validate(
            {
                "suite_id": "s",
                "suite_version": "v1",
                "created": "2026-09-29",
                "cases": [entry, dict(entry)],
            }
        )


def test_anchor_checks_path_and_type(tmp_path: Path):
    payload = json.loads(
        (SUITE_ROOT / "c2-benign-baseline" / "case.json").read_text(encoding="utf-8")
    )
    payload["judgment_target"]["file_path"] = "/elsewhere/agent"
    case_dir = tmp_path / "case"
    shutil_copytree(SUITE_ROOT / "c2-benign-baseline", case_dir)
    (case_dir / "case.json").write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    from threat_agent.capability_validation import ReplayBundle

    with pytest.raises(ValueError, match="path mismatch"):
        ReplayBundle.load(case_dir)


def test_manifest_artifact_limit_overrides_default(tmp_path: Path):
    suite = tmp_path / "suite"
    case_dir = suite / "case"
    (case_dir / "replay" / "artifacts").mkdir(parents=True)
    (case_dir / "replay" / "artifacts" / "small.bin").write_bytes(b"\0" * 100)
    (suite / "manifest.json").write_text(
        json.dumps(
            {
                "suite_id": "s",
                "suite_version": "v1",
                "created": "2026-09-29",
                "storage": {"artifact_max_bytes": 50},
                "cases": [{"case_id": "case", "directory": "case"}],
            }
        ),
        encoding="utf-8",
    )
    repo = ValidationSuiteRepository(suite)
    assert repo._artifact_limit(repo.load_manifest()) == 50
    # The manifest-declared limit is the one load() enforces (artifact is
    # 100 bytes; built-in default would allow it).
    with pytest.raises(ValueError, match="exceeds"):
        repo.load()


def shutil_copytree(src: Path, dst: Path) -> None:
    import shutil

    shutil.copytree(src, dst)


def test_derived_variant_ingests_through_reference_pipeline(tmp_path: Path):
    """The Step 01 acceptance gate: a derived variant loads into the very
    ingestion path the AI-side investigation runtime queries."""

    from threat_agent.contracts import DatasetManifest
    from threat_agent.data_foundation.adapters.activity_store import SQLiteActivityStore
    from threat_agent.data_foundation.adapters.parsers import ReferenceEventParser
    from threat_agent.data_foundation.application.ingestion import BatchIngestionService

    _, cases = _load_suite()
    item = cases["c2-malicious-elf"]
    (spec,) = item.case.parameters.variants
    derived = derive_variant(item.bundle, spec).derived

    store = SQLiteActivityStore(tmp_path / "activities.sqlite")
    parser = ReferenceEventParser()
    try:
        BatchIngestionService(store, parser).ingest_payloads(
            DatasetManifest(
                tenant_id="default",
                source_identity="capability-validation-test",
                dataset_id=derived.case.case_id,
                dataset_version="2026.09.1",
                batch_id=f"{derived.case.case_id}-2026.09.1",
                source_system="capability-validation",
                connector_version="test/1.0",
                parser_name=parser.name,
                parser_version=parser.version,
                expected_record_count=len(derived.events),
            ),
            derived.events,
        )
        assert store.count_raw_records("default") == len(derived.events)
        assert store.count_activities("default") > 0
        assert store.count_quarantined("default", f"{derived.case.case_id}-2026.09.1") == 0
    finally:
        store.close()
