"""Feature 18 unit gates: STIX mapping, lexical retrieval semantics and the
ATT&CK corpus supplier's contract behavior (statuses, catalog, fallbacks)."""

from __future__ import annotations

import json

from threat_agent.knowledge.adapters.attack_corpus import (
    AttackCorpusRecord,
    AttackCorpusSupplier,
    records_from_stix_bundle,
)
from threat_agent.knowledge.ports.supplier_retrieval import (
    SupplierRetrievalRequest,
    SupplierSourceQuery,
)


def _mini_bundle() -> dict:
    def attack_pattern(stix_id, external_id, *, name, revoked=False, deprecated=False, **extra):
        obj = {
            "type": "attack-pattern",
            "id": stix_id,
            "name": name,
            "description": f"{name} description for testing.",
            "external_references": [
                {"source_name": "capec", "external_id": "CAPEC-1"},
                {
                    "source_name": "mitre-attack",
                    "external_id": external_id,
                    "url": f"https://attack.mitre.org/techniques/{external_id.replace('.', '/')}/",
                },
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                {"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"},
                {"kill_chain_name": "not-attack", "phase_name": "ignored"},
            ],
        }
        obj.update(extra)
        if revoked:
            obj["revoked"] = True
        if deprecated:
            obj["x_mitre_deprecated"] = True
        return obj

    return {
        "objects": [
            {
                "type": "x-mitre-collection",
                "x_mitre_version": "19.2",
            },
            attack_pattern("ap-1", "T1053", name="Scheduled Task/Job"),
            attack_pattern(
                "ap-2",
                "T1053.003",
                name="Scheduled Task/Job: Cron",
                x_mitre_platforms=["Linux", "macOS"],
                x_mitre_data_sources=["Scheduled Job Store"],
            ),
            attack_pattern("ap-3", "T9999", name="Revoked Old Technique", revoked=True),
            attack_pattern("ap-4", "T8888.001", name="Deprecated Technique", deprecated=True),
            attack_pattern("ap-5", "no-tid", name="Technique without a TID reference"),
            {"type": "course-of-action", "id": "coa-1", "name": "mitigation"},
        ]
    }


def test_records_from_stix_bundle_filters_and_maps():
    records, counts = records_from_stix_bundle(_mini_bundle(), attack_version="19.2")

    assert [record.knowledge_id for record in records] == ["T1053", "T1053.003"]
    assert counts == {
        "kept": 2,
        "revoked": 1,
        "deprecated": 1,
        # only the no-TID attack-pattern counts here; the course-of-action
        # object is not an attack-pattern at all and is skipped entirely
        "non_technique": 1,
    }
    first, second = records
    assert first.version == "19.2"
    assert first.title_en == "Scheduled Task/Job"
    assert first.tactics == ["persistence", "privilege-escalation"]
    assert first.source_uri == "https://attack.mitre.org/techniques/T1053/"
    assert second.platforms == ["Linux", "macOS"]
    assert second.data_sources == ["Scheduled Job Store"]
    assert "Technique: Scheduled Task/Job: Cron (T1053.003)" in second.content_en
    # Chinese fields are build-time output; the pure mapping leaves them empty.
    assert second.title_zh == "" and second.summary_zh == "" and second.keywords == []


def _corpus_supplier() -> AttackCorpusSupplier:
    def record(tid, title_zh, summary_zh, keywords, content_en=""):
        return AttackCorpusRecord(
            knowledge_id=tid,
            version="19.2",
            title_en=title_zh.upper(),
            title_zh=title_zh,
            summary_zh=summary_zh,
            keywords=keywords,
            content_en=content_en or f"Technique: {title_zh.upper()} ({tid}). Long English body.",
            tactics=["persistence"],
            platforms=["Linux"],
            source_uri=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        )

    return AttackCorpusSupplier(
        records=[
            record(
                "T1053.003",
                "计划任务：Cron",
                "攻击者滥用 cron 计划任务实现定时执行与持久化，取证看新增任务条目与其创建进程。",
                ["计划任务", "cron", "定时执行", "持久化", "自启动"],
            ),
            record(
                "T1071.001",
                "应用层协议（Web）",
                "恶意软件借助 HTTPS 等应用层协议伪装合法流量建立 C2 通道，关注固定间隔信标行为。",
                ["回连", "外连", "信标", "c2", "https", "固定间隔"],
            ),
            record(
                "T1547.005",
                "服务执行与持久化",
                "攻击者新建或篡改系统服务实现开机自启，取证看服务单元文件新建记录。",
                ["服务", "systemd", "自启", "持久化"],
            ),
            record(
                "T1027",
                "文件与信息混淆",
                "攻击者对文件内容做编码混淆规避检测，解码确认实际动作后再定性。",
                ["混淆", "编码", "base64", "解码"],
            ),
        ]
    )


def _request(query_text: str, *, category="attack_technique", top_k=None):
    options = {"top_k": top_k} if top_k else {}
    return SupplierRetrievalRequest(
        query_id="kquery-test",
        tenant_id="tenant-a",
        case_id="case-1",
        actor_id="actor-1",
        timeout_seconds=10.0,
        sources=[SupplierSourceQuery(source_category=category, query_text=query_text, options=options)],
    )


def test_chinese_behavior_query_ranks_expected_techniques():
    supplier = _corpus_supplier()
    outcome = supplier.retrieve_sources(
        _request("已验证行为: 计划任务持久化; 已验证行为: 固定间隔回连")
    )[0]

    assert outcome.status == "available"
    ids = [item.knowledge_id for item in outcome.items]
    assert ids[0] == "T1053.003"
    assert "T1071.001" in ids
    # The obfuscation entry shares no vocabulary with the query: not returned.
    assert "T1027" not in ids
    top_item = outcome.items[0]
    assert "计划任务：Cron（" in top_item.title and "T1053.003" in top_item.title
    assert top_item.summary.startswith("攻击者滥用")
    assert top_item.source_uri.startswith("https://attack.mitre.org/")


def test_tid_exact_channel_wins_even_without_vocabulary_overlap():
    supplier = _corpus_supplier()
    outcome = supplier.retrieve_sources(_request("待验证假设: 行为是否对应 t1071.001 通道"))[0]

    assert outcome.status == "available"
    assert outcome.items[0].knowledge_id == "T1071.001"
    assert outcome.items[0].relevance == "high"
    assert outcome.diagnostics["raw_scores"][0]["tid_match"] is True


def test_unrelated_query_reports_empty_instead_of_noise():
    supplier = _corpus_supplier()
    outcome = supplier.retrieve_sources(_request("待验证假设: 备份软件窗口重叠"))[0]

    assert outcome.status == "empty"
    assert outcome.items == []


def test_english_fallback_when_chinese_fields_missing():
    supplier = AttackCorpusSupplier(
        records=[
            AttackCorpusRecord(
                knowledge_id="T1005",
                version="19.2",
                title_en="Data from Local System",
                content_en="Technique: Data from Local System (T1005). Description sentence one. Sentence two.",
                tactics=["collection"],
                source_uri="https://attack.mitre.org/techniques/T1005/",
            )
        ]
    )
    outcome = supplier.retrieve_sources(_request("data local system collection"))[0]

    assert outcome.status == "available"
    item = outcome.items[0]
    assert item.title == "Data from Local System（T1005）"
    assert item.summary.startswith("Technique: Data from Local System")


def test_missing_corpus_file_reports_not_configured(tmp_path):
    supplier = AttackCorpusSupplier(corpus_path=tmp_path / "absent.jsonl")
    outcome = supplier.retrieve_sources(_request("计划任务持久化"))[0]

    assert outcome.status == "not_configured"
    assert outcome.limitations and "不存在" in outcome.limitations[0]
    assert supplier.catalog() is None


def test_other_source_categories_are_rejected_as_not_configured():
    supplier = _corpus_supplier()
    outcome = supplier.retrieve_sources(
        _request("计划任务", category="org_sop")
    )[0]

    assert outcome.status == "not_configured"
    assert outcome.source_category == "org_sop"


def test_catalog_shape_matches_reference_contract():
    supplier = _corpus_supplier()
    catalog = supplier.catalog()

    assert catalog["supplier_id"] == "attack-corpus"
    assert catalog["attack_version"] == "19.2"
    (category,) = catalog["categories"]
    assert category["category"] == "attack_technique"
    assert len(category["items"]) == 4
    assert all(item.get("restricted_to_tenant") is None for item in category["items"])


def test_jsonl_roundtrip_through_the_file(tmp_path):
    record = AttackCorpusRecord(
        knowledge_id="T1053.003",
        version="19.2",
        title_en="Scheduled Task/Job: Cron",
        title_zh="计划任务：Cron",
        summary_zh="攻击者滥用 cron 计划任务实现定时执行与持久化。",
        keywords=["计划任务", "cron", "持久化"],
        content_en="Technique: Scheduled Task/Job: Cron (T1053.003). Body.",
        tactics=["persistence"],
        platforms=["Linux"],
        source_uri="https://attack.mitre.org/techniques/T1053/003/",
    )
    path = tmp_path / "attack_technique.jsonl"
    path.write_text(record.model_dump_json() + "\n", encoding="utf-8")

    reloaded = AttackCorpusSupplier(corpus_path=path)
    outcome = reloaded.retrieve_sources(_request("计划任务持久化"))[0]

    assert outcome.status == "available"
    assert outcome.items[0].knowledge_id == "T1053.003"
    assert outcome.items[0].title.startswith("计划任务：Cron（")
