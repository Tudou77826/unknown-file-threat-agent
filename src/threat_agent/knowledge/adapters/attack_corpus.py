"""ATT&CK file-backed corpus supplier (Feature 18).

The corpus is a versioned JSONL file built offline by
``scripts/build_attack_corpus.py`` from MITRE ATT&CK STIX data (CC BY 4.0),
with one Chinese summary/keyword line per technique generated once at build
time by the LLM and frozen into the file. Runtime retrieval is dependency-free
lexical matching — CJK character bigrams plus ASCII word tokens over the
bilingual entry text, with a T-ID exact channel — fully deterministic, no
network, no model calls. This is a validation-grade placeholder: the intranet
RAG replaces this adapter behind the same port with zero business change.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from pydantic import Field

from ...shared import StrictModel
from ..ports.supplier_retrieval import (
    SupplierItem,
    SupplierRetrievalRequest,
    SupplierRetrievalPort,
    SupplierSourceOutcome,
    SupplierSourceQuery,
)

DEFAULT_ATTACK_CORPUS_PATH = Path(__file__).resolve().parents[4] / "corpora" / "attack_technique.jsonl"

_CORPUS_BUILDER = "attack-corpus/1"

# T1053 / T1053.003 — the only identifier shapes ATT&CK techniques use.
_TID_STRICT = re.compile(r"T\d{4}(?:\.\d{3})?")
_TID_QUERY = re.compile(r"t\d{4}(?:\.\d{3})?", re.IGNORECASE)

_CJK_RUN = re.compile(r"[\u4e00-\u9fff]+")
_ASCII_WORD = re.compile(r"[a-z0-9]+")

# Relevance normalization thresholds (calibrated on the real corpus with
# Chinese behavior sentences; see tests/test_attack_corpus_supplier.py).
# Entries scoring below the medium band are not returned at all — accidental
# bigram hits on a 700-entry corpus cluster around 0.13-0.20 while genuine
# behavior-sentence hits start around 0.33, so the floor keeps noise out of
# the guidance without a recall cost.
_THRESHOLD_HIGH = 0.45
_THRESHOLD_MEDIUM = 0.25

# Lexical token weights: an ASCII word hit (cron, persistence) is a strong
# signal, a single CJK bigram hit is noise (the bigram space is dense — any
# two texts share some 2-gram). Entries qualify only with at least one ASCII
# word hit or two CJK bigram hits.
_WORD_WEIGHT = 1.0
_BIGRAM_WEIGHT = 0.6

# Model-context protection: supplier content is capped so top_k=3 items stay
# a bounded addition to the investigation context.
_MAX_CONTENT_CHARS = 1600


class AttackCorpusRecord(StrictModel):
    """One JSONL line of the ATT&CK corpus; Chinese fields are build-time
    LLM output and may be empty (English fallback keeps the entry usable)."""

    knowledge_id: str
    version: str
    chunk_id: str = "c1"
    title_en: str
    title_zh: str = ""
    summary_zh: str = ""
    keywords: list[str] = Field(default_factory=list)
    content_en: str
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    source_uri: str
    built_by: str = _CORPUS_BUILDER


class AttackCorpusSupplier(SupplierRetrievalPort):
    """Serves the ``attack_technique`` source from the offline-built corpus."""

    supplier_id = "attack-corpus"

    def __init__(
        self,
        *,
        corpus_path: Path | None = None,
        records: list[AttackCorpusRecord] | None = None,
    ):
        self.corpus_path = Path(corpus_path) if corpus_path is not None else DEFAULT_ATTACK_CORPUS_PATH
        self._records: list[AttackCorpusRecord] = []
        self._load_limitation: str | None = None
        if records is not None:
            self._records = sorted(records, key=lambda record: record.knowledge_id)
        else:
            self._load()
        self._index = [(record, _entry_tokens(record)) for record in self._records]

    def _load(self) -> None:
        if not self.corpus_path.exists():
            self._load_limitation = f"ATT&CK 语料文件不存在：{self.corpus_path}"
            return
        records: list[AttackCorpusRecord] = []
        with self.corpus_path.open(encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(AttackCorpusRecord.model_validate(json.loads(line)))
                except Exception as error:  # noqa: BLE001 — 单行损坏只跳过该行并计数
                    self._load_limitation = (
                        f"语料第 {line_no} 行无法解析（{type(error).__name__}），已跳过"
                    )
        self._records = sorted(records, key=lambda record: record.knowledge_id)

    # -- SupplierRetrievalPort ------------------------------------------------

    def retrieve_sources(
        self, request: SupplierRetrievalRequest
    ) -> list[SupplierSourceOutcome]:
        return [self._retrieve_one(query) for query in request.sources]

    def catalog(self) -> dict[str, Any] | None:
        if not self._records:
            return None
        versions = sorted({record.version for record in self._records})
        items = [
            {
                "knowledge_id": record.knowledge_id,
                "version": record.version,
                "title": _display_title(record),
                "summary": _display_summary(record),
                "restricted_to_tenant": None,
            }
            for record in self._records
        ]
        return {
            "supplier_id": self.supplier_id,
            "attack_version": versions[-1] if len(versions) == 1 else "/".join(versions),
            "categories": [
                {"category": "attack_technique", "items": items},
            ],
        }

    # -- internals -----------------------------------------------------------

    def _retrieve_one(self, query: SupplierSourceQuery) -> SupplierSourceOutcome:
        if query.source_category != "attack_technique":
            return SupplierSourceOutcome(
                source_category=query.source_category,
                status="not_configured",
                limitations=["attack-corpus 供应方只服务 attack_technique 知识源"],
                diagnostics={"supplier_id": self.supplier_id},
            )
        if not self._records:
            limitation = self._load_limitation or "ATT&CK 语料为空：请先运行 scripts/build_attack_corpus.py"
            return SupplierSourceOutcome(
                source_category=query.source_category,
                status="not_configured",
                limitations=[limitation],
                diagnostics={"supplier_id": self.supplier_id},
            )

        query_tokens = _tokens(query.query_text)
        query_tids = {
            match.group(0).upper() for match in _TID_QUERY.finditer(query.query_text)
        }
        top_k = int(query.options.get("top_k", 3))

        scored: list[tuple[float, int, bool, AttackCorpusRecord]] = []
        for record, entry_tokens in self._index:
            exact = record.knowledge_id in query_tids
            overlap, hits = _weighted_overlap(entry_tokens, query_tokens)
            if hits == 0 and not exact:
                continue
            score = 1.0 if exact else overlap / max(1.0, math.sqrt(len(entry_tokens)))
            if not exact and score < _THRESHOLD_MEDIUM:
                continue  # 低于中档线的命中按噪音丢弃，宁缺毋滥
            scored.append((score, hits, exact, record))
        scored.sort(key=lambda item: (-item[0], -item[1], item[3].knowledge_id))

        raw_scores: list[dict[str, Any]] = []
        items: list[SupplierItem] = []
        for score, hits, exact, record in scored[:top_k]:
            raw_scores.append(
                {
                    "knowledge_id": record.knowledge_id,
                    "chunk_id": record.chunk_id,
                    "raw_score": round(score, 4),
                    "token_hits": hits,
                    "tid_match": exact,
                }
            )
            items.append(_to_supplier_item(record, _relevance(score)))

        limitations: list[str] = []
        if self._load_limitation:
            limitations.append(self._load_limitation)
        return SupplierSourceOutcome(
            source_category=query.source_category,
            status="available" if items else "empty",
            items=items,
            limitations=limitations,
            diagnostics={"supplier_id": self.supplier_id, "raw_scores": raw_scores},
        )


# ---------------------------------------------------------------------------
# Corpus building: pure STIX -> record mapping (shared with the build script).
# ---------------------------------------------------------------------------

def records_from_stix_bundle(
    bundle: dict[str, Any],
    *,
    attack_version: str,
) -> tuple[list[AttackCorpusRecord], dict[str, int]]:
    """Map an ATT&CK STIX 2.1 bundle to corpus records.

    Enterprise attack-pattern objects only: revoked and deprecated objects are
    dropped, and the identifier must be a strict TID. Returns the records plus
    a small count report (kept/revoked/deprecated/non_technique) so the build
    script can print an honest summary.
    """

    records: list[AttackCorpusRecord] = []
    counts = {"kept": 0, "revoked": 0, "deprecated": 0, "non_technique": 0}
    for obj in bundle.get("objects", []):
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked"):
            counts["revoked"] += 1
            continue
        if obj.get("x_mitre_deprecated"):
            counts["deprecated"] += 1
            continue
        reference = next(
            (
                ref
                for ref in obj.get("external_references") or []
                if _TID_STRICT.fullmatch(str(ref.get("external_id") or "").upper())
            ),
            None,
        )
        if reference is None:
            counts["non_technique"] += 1
            continue
        tid = str(reference["external_id"]).upper()
        title_en = str(obj.get("name") or tid).strip()
        description = str(obj.get("description") or "").strip()
        detection = str(obj.get("x_mitre_detection") or "").strip()
        tactics = sorted(
            {
                str(phase.get("phase_name"))
                for phase in obj.get("kill_chain_phases") or []
                if phase.get("phase_name") and phase.get("kill_chain_name") == "mitre-attack"
            }
        )
        platforms = sorted({str(value) for value in obj.get("x_mitre_platforms") or []})
        data_sources = sorted({str(value) for value in obj.get("x_mitre_data_sources") or []})
        content_parts = [
            f"Technique: {title_en} ({tid})",
            f"Tactics: {', '.join(tactics) or '—'}; Platforms: {', '.join(platforms) or '—'}",
            f"Data sources: {', '.join(data_sources) or '—'}",
        ]
        if description:
            content_parts.append(f"Description: {description}")
        if detection and detection != description:
            content_parts.append(f"Detection: {detection}")
        records.append(
            AttackCorpusRecord(
                knowledge_id=tid,
                version=attack_version,
                title_en=title_en,
                content_en="\n".join(content_parts),
                tactics=tactics,
                platforms=platforms,
                data_sources=data_sources,
                source_uri=str(
                    reference.get("url")
                    or f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
                ),
            )
        )
        counts["kept"] += 1
    records.sort(key=lambda record: record.knowledge_id)
    return records, counts


# ---------------------------------------------------------------------------
# Lexical scoring helpers (deterministic, dependency-free).
# ---------------------------------------------------------------------------

def _tokens(text: str) -> set[str]:
    """CJK runs become character bigrams, ASCII runs become lowercase words.

    Bigrams are the standard segmenter-free Chinese lexical unit: they let
    计划任务 in a query overlap 计划/划任/任务 in an entry without any
    segmentation model. Query label prefixes (已验证行为: etc.) never overlap
    entry vocabulary, so they are left in place.
    """

    lowered = text.lower()
    tokens: set[str] = set()
    for run in _CJK_RUN.findall(lowered):
        if len(run) == 1:
            tokens.add(run)
        else:
            tokens.update(run[i : i + 2] for i in range(len(run) - 1))
    tokens.update(word for word in _ASCII_WORD.findall(lowered) if len(word) >= 2)
    return tokens


def _entry_tokens(record: AttackCorpusRecord) -> set[str]:
    surface = " ".join(
        [
            record.title_zh,
            record.summary_zh,
            " ".join(record.keywords),
            record.title_en,
            " ".join(record.tactics),
        ]
    )
    return _tokens(surface)


def _weighted_overlap(entry_tokens: set[str], query_tokens: set[str]) -> tuple[float, int]:
    """Weighted token overlap plus raw hit count.

    ASCII word hits weigh 1.0, CJK bigram hits 0.6. Entries with only a single
    bigram hit are treated as noise (0.0) — the CJK bigram space is dense
    enough that any two texts share one by accident (备份软件 vs 恶意软件).
    """

    intersection = entry_tokens & query_tokens
    words = sum(1 for token in intersection if token.isascii())
    bigrams = len(intersection) - words
    if words == 0 and bigrams < 2:
        return 0.0, 0
    return words * _WORD_WEIGHT + bigrams * _BIGRAM_WEIGHT, len(intersection)


def _relevance(score: float) -> str:
    if score >= _THRESHOLD_HIGH:
        return "high"
    if score >= _THRESHOLD_MEDIUM:
        return "medium"
    return "low"


_TITLE_TID_SUFFIX = re.compile(r"[（(]\s*T\d{4}(?:\.\d{3})?\s*[）)]\s*$")


def _display_title(record: AttackCorpusRecord) -> str:
    title_zh = _TITLE_TID_SUFFIX.sub("", record.title_zh).strip()
    if title_zh:
        return f"{title_zh}（{record.title_en}，{record.knowledge_id}）"
    return f"{record.title_en}（{record.knowledge_id}）"


def _display_summary(record: AttackCorpusRecord) -> str:
    if record.summary_zh:
        return record.summary_zh
    sentences = re.split(r"(?<=[.!?])\s+", record.content_en)
    return " ".join(sentences[:2])[:200]


def _to_supplier_item(record: AttackCorpusRecord, relevance: str) -> SupplierItem:
    content = record.summary_zh + "\n" + record.content_en if record.summary_zh else record.content_en
    return SupplierItem(
        knowledge_id=record.knowledge_id,
        version=record.version,
        chunk_id=record.chunk_id,
        title=_display_title(record),
        summary=_display_summary(record),
        content=content[:_MAX_CONTENT_CHARS],
        source_uri=record.source_uri,
        relevance=relevance,
        item_limitations=[],
        supplier_metadata={
            "tactics": list(record.tactics),
            "platforms": list(record.platforms),
            "data_sources": list(record.data_sources[:6]),
        },
    )
