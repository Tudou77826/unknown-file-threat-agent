from pathlib import Path

from threat_agent.contracts import EvidenceQuery, Scope
from threat_agent.data_foundation.adapters import SQLiteEvidenceQueryAdapter, SQLiteReferenceDataStore
from threat_agent.data_foundation.application import initialize_reference_demo


ROOT = Path(__file__).parents[1]
VERSION = "2026.08.1"


def test_profiles_only_change_reference_data_visibility(tmp_path):
    store = SQLiteReferenceDataStore(tmp_path / "reference.sqlite")
    datasets = initialize_reference_demo(store, project_root=ROOT)
    metadata = datasets["c2-malicious-reference"]
    case_id = store.connection.execute(
        "SELECT case_id FROM cases WHERE dataset_id=?", (metadata.dataset_id,)
    ).fetchone()["case_id"]
    counts = []
    for profile_id in [
        "l0-alert-only",
        "l1-process-context",
        "l2-behavior-telemetry",
        "l3-attribution-and-assets",
    ]:
        profile = store.get_profile(metadata.dataset_id, VERSION, profile_id)
        adapter = SQLiteEvidenceQueryAdapter(
            store,
            dataset_id=metadata.dataset_id,
            dataset_version=VERSION,
            profile=profile,
        )
        result = adapter.query_evidence(
            EvidenceQuery(
                tenant_id="demo",
                case_id=case_id,
                source_identity="test",
                query_id=f"q-{profile.level}",
                domain="process",
                evidence_types=["process_exec", "process_parent_relation", "child_process_exec"],
                scope=Scope(host_ids=["server-01"]),
            )
        )
        counts.append(len(result.evidence))
    assert counts == [0, 4, 5, 5]
    assert store.get_dataset(metadata.dataset_id, VERSION).content_digest == metadata.content_digest


def test_profile_version_mismatch_fails_explicitly(tmp_path):
    store = SQLiteReferenceDataStore(tmp_path / "reference.sqlite")
    initialize_reference_demo(store, project_root=ROOT)
    profile = store.get_profile("c2-malicious-reference", VERSION, "l1-process-context")
    try:
        SQLiteEvidenceQueryAdapter(
            store,
            dataset_id="c2-malicious-reference",
            dataset_version="different",
            profile=profile,
        )
    except ValueError as error:
        assert "dataset_version" in str(error)
    else:
        raise AssertionError("Expected an explicit profile version mismatch")
