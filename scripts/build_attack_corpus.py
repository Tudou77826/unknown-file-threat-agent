"""Build the ATT&CK corpus JSONL offline (Feature 18).

Pipeline: download the MITRE ATT&CK Enterprise STIX 2.1 bundle (cached under
downloads/), map attack-pattern objects to corpus records via the pure
function in threat_agent.knowledge.adapters.attack_corpus, generate Chinese
title/summary/keywords once per technique through the configured chat model
(cache keyed by TID under corpora/attack_llm_cache.json), and write the
versioned corpus file consumed by AttackCorpusSupplier.

ATT&CK data is CC BY 4.0; every record keeps its official attack.mitre.org
URI as attribution. Re-runs are idempotent: cached TIDs are not re-called.

Usage examples:
  python scripts/build_attack_corpus.py --limit 20     # smoke build
  python scripts/build_attack_corpus.py               # full build
  python scripts/build_attack_corpus.py --no-llm      # English-only rebuild
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from threat_agent.bootstrap.settings import AppSettings, build_chat_model  # noqa: E402
from threat_agent.knowledge.adapters.attack_corpus import (  # noqa: E402
    AttackCorpusRecord,
    records_from_stix_bundle,
)

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DOWNLOAD_PATH = PROJECT_ROOT / "downloads" / "enterprise-attack.json"
CACHE_PATH = PROJECT_ROOT / "corpora" / "attack_llm_cache.json"
OUTPUT_PATH = PROJECT_ROOT / "corpora" / "attack_technique.jsonl"

_EN_STOPWORDS = {
    "the", "and", "for", "with", "via", "using", "from", "into", "that",
    "this", "are", "not", "its", "when", "which", "such", "over", "under",
    "their", "them", "then", "than", "have", "has", "been", "will", "can",
    "may", "also", "used", "use", "other", "others", "may", "account",
    "accounts",
}

_SYSTEM_PROMPT = (
    "你是安全知识库编辑，为 MITRE ATT&CK 攻击技术条目补写中文信息。"
    "只输出一个 JSON 对象，不要输出任何其他文字、解释或代码块标记。"
)

def _user_prompt(record: AttackCorpusRecord) -> str:
    return (
        f"ATT&CK 技术 {record.knowledge_id}：{record.title_en}\n"
        f"战术：{', '.join(record.tactics) or '—'}\n"
        f"平台：{', '.join(record.platforms) or '—'}\n"
        f"数据源：{', '.join(record.data_sources) or '—'}\n"
        f"原文：{record.content_en[:1200]}\n\n"
        "生成 JSON：{\"title_zh\": \"中文技术名（术语风格，保留必要的英文缩写）\", "
        "\"summary_zh\": \"中文摘要，60-100字，研判视角：说明攻击者用它做什么、"
        "典型取证点或检测线索\", \"keywords_zh\": [\"4-8个中文关键词，"
        "包含中国安全分析师常用的同义说法（如：回连、外连、信标、持久化、落地、"
        "横向移动、命令执行、提权、窃取、混淆……只列适用于该技术的）\"]}"
    )


def _parse_llm_json(text: str) -> dict | None:
    cleaned = re.sub(r"```(?:json)?", "", text).strip().strip("`").strip()
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    title = str(data.get("title_zh") or "").strip()
    summary = str(data.get("summary_zh") or "").strip()
    keywords = data.get("keywords_zh")
    if not (2 <= len(title) <= 60):
        return None
    title = re.sub(r"[（(]\s*T\d{4}(?:\.\d{3})?\s*[）)]\s*$", "", title).strip() or title
    if not (20 <= len(summary) <= 400):
        return None
    if not isinstance(keywords, list) or not keywords:
        return None
    cleaned_keywords = [str(kw).strip() for kw in keywords if 2 <= len(str(kw).strip()) <= 20]
    if len(cleaned_keywords) < 2:
        return None
    return {"title_zh": title, "summary_zh": summary, "keywords_zh": cleaned_keywords[:10]}


def _sinicize_one(model, record: AttackCorpusRecord) -> dict | None:
    from langchain_core.messages import HumanMessage, SystemMessage

    messages = [SystemMessage(content=_SYSTEM_PROMPT), HumanMessage(content=_user_prompt(record))]
    for attempt in range(2):
        try:
            response = model.invoke(messages)
        except Exception as error:  # noqa: BLE001 — 单条失败跳过，缓存不落脏数据
            print(f"  [llm-error] {record.knowledge_id}: {type(error).__name__}: {error}")
            return None
        parsed = _parse_llm_json(getattr(response, "text", "") or str(response))
        if parsed is not None:
            return parsed
        messages = messages[:2] + [
            HumanMessage(content="上一次输出不是合法 JSON 或字段不合规，请只输出符合要求的 JSON 对象。")
        ]
        if attempt == 1:
            print(f"  [llm-format] {record.knowledge_id}: two invalid responses, skipped")
    return None


def _merged_keywords(record: AttackCorpusRecord, zh_keywords: list[str]) -> list[str]:
    keywords = list(dict.fromkeys(zh_keywords))
    for tactic in record.tactics:
        keywords.append(tactic)
    for word in re.findall(r"[A-Za-z0-9]{3,}", record.title_en.lower()):
        if word not in _EN_STOPWORDS:
            keywords.append(word)
    keywords.append(record.knowledge_id.lower())
    return list(dict.fromkeys(keywords))[:16]


def _load_bundle(source: str, refresh: bool) -> dict:
    if re.match(r"^https?://", source):
        if DOWNLOAD_PATH.exists() and not refresh:
            print(f"[cache] reusing {DOWNLOAD_PATH}")
        else:
            DOWNLOAD_PATH.parent.mkdir(parents=True, exist_ok=True)
            print(f"[download] {source}")
            urllib.request.urlretrieve(source, DOWNLOAD_PATH)
            print(f"[download] saved {DOWNLOAD_PATH.stat().st_size / 1e6:.1f} MB")
        bundle_path = DOWNLOAD_PATH
    else:
        bundle_path = PROJECT_ROOT / source
    return json.loads(bundle_path.read_text(encoding="utf-8"))


def _detect_attack_version(bundle: dict, fallback: str) -> str:
    for obj in bundle.get("objects", []):
        if isinstance(obj, dict) and obj.get("type") == "x-mitre-collection":
            for key in ("x_mitre_version", "version"):
                value = obj.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return fallback


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=DEFAULT_SOURCE_URL,
                        help="STIX bundle URL or path (default: official enterprise-attack.json)")
    parser.add_argument("--version", default="unknown", help="ATT&CK version stamp")
    parser.add_argument("--limit", type=int, default=None, help="only build the first N records")
    parser.add_argument("--no-llm", action="store_true", help="skip Chinese generation")
    parser.add_argument("--refresh-llm", action="store_true", help="ignore and rebuild the LLM cache")
    parser.add_argument("--refresh-source", action="store_true", help="re-download the STIX bundle")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--out", default=str(OUTPUT_PATH))
    args = parser.parse_args()

    bundle = _load_bundle(args.source, args.refresh_source)
    detected = _detect_attack_version(bundle, args.version)
    print(f"[parse] attack version = {detected}")
    records, counts = records_from_stix_bundle(bundle, attack_version=detected)
    print(f"[parse] {counts}")
    if not records:
        print("[parse] no records, aborting")
        return 1
    if args.limit:
        records = records[: args.limit]
        print(f"[parse] limited to {len(records)} records")

    cache: dict[str, dict] = {}
    if args.refresh_llm or args.no_llm:
        if args.refresh_llm:
            print("[llm] cache refresh requested")
    elif CACHE_PATH.exists():
        cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        print(f"[llm] cache loaded: {len(cache)} entries")

    pending = [r for r in records if r.knowledge_id not in cache]
    if args.no_llm:
        print("[llm] skipped (--no-llm)")
    elif pending:
        settings = AppSettings.load()
        model = build_chat_model(settings.judgment_model)
        print(f"[llm] {len(pending)} techniques to generate, workers={args.workers}")
        started = time.time()
        done = 0
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {
                pool.submit(_sinicize_one, model, record): record.knowledge_id
                for record in pending
            }
            for future in as_completed(futures):
                tid = futures[future]
                result = future.result()
                if result is not None:
                    cache[tid] = result
                done += 1
                if done % 25 == 0 or done == len(pending):
                    rate = done / max(0.1, time.time() - started)
                    print(f"[llm] {done}/{len(pending)} ({rate:.1f}/s)")
                    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
                    CACHE_PATH.write_text(
                        json.dumps(cache, ensure_ascii=False, indent=0), encoding="utf-8"
                    )
    else:
        print("[llm] all cached, no calls needed")

    if not args.no_llm:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=False, indent=0), encoding="utf-8")

    lines: list[str] = []
    zh_count = 0
    for record in records:
        entry = cache.get(record.knowledge_id)
        if entry:
            record = record.model_copy(update={
                "title_zh": entry["title_zh"],
                "summary_zh": entry["summary_zh"],
                "keywords": _merged_keywords(record, entry["keywords_zh"]),
            })
            zh_count += 1
        else:
            record = record.model_copy(update={
                "keywords": _merged_keywords(record, []),
            })
        lines.append(record.model_dump_json())
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"[write] {out_path}: {len(lines)} records, "
        f"{zh_count} with Chinese ({len(lines) - zh_count} English-only)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
