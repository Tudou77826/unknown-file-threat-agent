import json
from pathlib import Path

from threat_agent.contracts import EvidenceQuery, Scope
from threat_agent.data_foundation import SQLiteEvidenceQueryAdapter, SQLiteReferenceDataStore


ROOT = Path(__file__).resolve().parents[1]


def test_reference_store_import_is_idempotent_and_queryable(tmp_path: Path):
    store = SQLiteReferenceDataStore(tmp_path / "reference.sqlite")
    case_dir = ROOT / "cases" / "c2_malicious"
    raw = json.loads((case_dir / "input.json").read_text(encoding="utf-8"))
    metadata = store.import_case_directory(
        case_dir,
        dataset_id="c2-malicious-reference",
        dataset_version="1.0",
        label="malicious_reference",
        random_seed=7,
    )
    case_id = "case-a06b4392935d"
    first_count = store.count_evidence(metadata.dataset_id, metadata.dataset_version, case_id)
    store.import_case_directory(
        case_dir,
        dataset_id="c2-malicious-reference",
        dataset_version="1.0",
        label="malicious_reference",
        random_seed=7,
    )
    assert store.count_evidence(metadata.dataset_id, metadata.dataset_version, case_id) == first_count
    assert first_count > 0

    adapter = SQLiteEvidenceQueryAdapter(
        store,
        dataset_id=metadata.dataset_id,
        dataset_version=metadata.dataset_version,
    )
    result = adapter.query_evidence(
        EvidenceQuery(
            tenant_id="default",
            case_id=case_id,
            query_id="query-process",
            domain="process",
            evidence_types=["process_exec"],
            scope=Scope(host_ids=[str(raw["Sub_asset"])], allowed_domains=["process"]),
        )
    )
    assert result.status.value == "available"
    assert {item.evidence_type for item in result.evidence} == {"process_exec"}
    assert all(item.raw_reference.startswith("reference-jsonl://") for item in result.evidence)
    store.close()


def test_reference_query_distinguishes_unavailable_from_empty(tmp_path: Path):
    store = SQLiteReferenceDataStore(tmp_path / "reference.sqlite")
    case_dir = ROOT / "cases" / "c2_malicious"
    store.import_case_directory(
        case_dir,
        dataset_id="reference",
        dataset_version="1.0",
        label="malicious_reference",
        random_seed=7,
    )
    adapter = SQLiteEvidenceQueryAdapter(
        store, dataset_id="reference", dataset_version="1.0", visible_sources=set()
    )
    result = adapter.query_evidence(
        EvidenceQuery(
            tenant_id="default",
            case_id="case-a06b4392935d",
            query_id="query-hidden",
            domain="process",
            evidence_types=["process_exec"],
            scope=Scope(host_ids=["server-01"], allowed_domains=["process"]),
        )
    )
    assert result.status.value == "unavailable"
    assert result.evidence == []
    store.close()
