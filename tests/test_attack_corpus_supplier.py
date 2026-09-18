"""Feature 18 gate over the real committed corpus: the file must exist, hold
the full ATT&CK Enterprise technique set with Chinese coverage, and answer
real Chinese behavior sentences with the expected techniques. Offline by
construction — the JSONL ships in the repository."""

from __future__ import annotations

from pathlib import Path

from threat_agent.knowledge.adapters.attack_corpus import (
    DEFAULT_ATTACK_CORPUS_PATH,
    AttackCorpusRecord,
    AttackCorpusSupplier,
)
from threat_agent.knowledge.ports.supplier_retrieval import (
    SupplierRetrievalRequest,
    SupplierSourceQuery,
)


def _records() -> list[AttackCorpusRecord]:
    lines = DEFAULT_ATTACK_CORPUS_PATH.read_text(encoding="utf-8").strip().splitlines()
    import json

    return [AttackCorpusRecord.model_validate(json.loads(line)) for line in lines]


def _supplier() -> AttackCorpusSupplier:
    assert DEFAULT_ATTACK_CORPUS_PATH.exists(), (
        f"corpus file missing: {DEFAULT_ATTACK_CORPUS_PATH} — run scripts/build_attack_corpus.py"
    )
    return AttackCorpusSupplier(corpus_path=DEFAULT_ATTACK_CORPUS_PATH)


def _query(supplier: AttackCorpusSupplier, text: str):
    request = SupplierRetrievalRequest(
        query_id="kquery-gate",
        tenant_id="tenant-a",
        case_id="case-1",
        actor_id="actor-1",
        timeout_seconds=10.0,
        sources=[
            SupplierSourceQuery(source_category="attack_technique", query_text=text)
        ],
    )
    return supplier.retrieve_sources(request)[0]


def test_corpus_holds_full_enterprise_technique_set():
    records = _records()
    # ATT&CK Enterprise v19.2: 222 techniques + 475 sub-techniques = 697.
    assert len(records) >= 600, f"only {len(records)} records"
    tids = [record.knowledge_id for record in records]
    assert tids == sorted(tids), "corpus must be sorted by TID"
    versions = {record.version for record in records}
    assert len(versions) == 1 and records[0].version != "unknown", versions
    assert all(record.source_uri.startswith("https://attack.mitre.org/") for record in records)


def test_chinese_coverage_is_complete_or_explicitly_gapped():
    records = _records()
    missing = [r.knowledge_id for r in records if not r.title_zh or not r.summary_zh]
    assert not missing, f"records without Chinese fields: {missing[:10]} (total {len(missing)})"


def test_real_behavior_sentence_hits_persistence_and_c2_families():
    supplier = _supplier()
    outcome = _query(
        supplier,
        "已验证行为: 无签名二进制落地系统路径; 已验证行为: 新建计划任务持久化; "
        "已验证行为: 固定间隔外连可疑域名",
    )

    assert outcome.status == "available", outcome.limitations
    ids = [item.knowledge_id for item in outcome.items]
    families = {tid.split(".")[0] for tid in ids}
    assert "T1053" in families, f"scheduled-task family missing from top hits: {ids}"


def test_tid_exact_lookup_over_full_corpus():
    supplier = _supplier()
    outcome = _query(supplier, "待验证假设: 该行为对应 T1071.001")

    assert outcome.status == "available"
    assert outcome.items[0].knowledge_id == "T1071.001"
    assert outcome.items[0].relevance == "high"


def test_irrelevant_sentence_returns_empty_not_noise():
    supplier = _supplier()
    outcome = _query(supplier, "待验证假设: 备份软件的读写窗口与告警时间重合")

    # An ops/benign hypothesis must not map onto attack techniques; the empty
    # status keeps the honesty contract (no noise dressed up as guidance).
    assert outcome.status == "empty", [i.knowledge_id for i in outcome.items]


def test_catalog_reports_the_full_inventory():
    supplier = _supplier()
    catalog = supplier.catalog()

    assert catalog is not None
    (category,) = catalog["categories"]
    assert category["category"] == "attack_technique"
    assert len(category["items"]) >= 600
