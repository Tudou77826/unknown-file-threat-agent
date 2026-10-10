"""Assembled report pipeline: one judgment call plus deterministic assembly.

Division of labor (the pipeline's contract):

- The LLM emits ONE judgment-shaped object — conclusions, statement texts,
  scenario names, open questions — citing evidence through SHORT pointers
  (``a003``/``e001``/``r002``/``q001``) minted from the run's citation
  whitelist. No transcription of long IDs, timestamps, hosts or numbering:
  selection is judgment, transcription is not.
- Code assembles the published ``ReportDraft`` from the ledger: resolves
  pointers to canonical IDs, numbers statements, fills query boundaries,
  asserted hosts/times and the supporting-reference union. The published
  shape is byte-for-byte the legacy one; only the production method changes.
- Repair is tiered. Deterministic backstops first (refill/clamp/strip —
  never generate, never alter a natural-language claim); only semantic
  failures (a unit with no usable citation) go back to the model as a
  minimal-edit re-judgment of the small judgment object, not a full
  15-22k ReportDraft rewrite.
- Degradation: if the judgment call exhausts its parse budget, the flow
  returns ``None`` and the caller falls back to the legacy compose/rejudge
  path — a run is never lost to this optimization.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from pydantic import Field

from ...contracts.investigation import CandidateVerdict, VerdictLevel
from ...shared import StrictModel
from ...shared.llm import forced_structured, invoke_llm, structured_output_method
from ..domain.models import InvestigationState
from .memory_store import MemoryStore
from .report_draft import ReportDraft
from .report_validation import (
    ReportGroundingValidator,
    ReportValidationIssue,
    candidate_relation_ids,
    executed_query_ids,
    known_out_of_scope_refs,
    resolved_relation_ids,
)
from .reporting import DeterministicFallbackBuilder, ReportPublisher, StructuredReportComposer, report_context

ThreatType = Literal["backdoor_c2", "data_exfiltration", "ransomware", "other", "unknown"]

_SECTION_PREFIX = {
    "current_situation": "cs",
    "affected_scope": "as",
    "key_evidence": "ke",
    "counter_evidence": "ce",
}


class JudgmentUnit(StrictModel):
    """One natural-language statement plus its citation pointers."""

    section: Literal["current_situation", "affected_scope", "key_evidence", "counter_evidence"]
    text: str = Field(min_length=1)
    refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class InvestigationJudgment(StrictModel):
    """The judgment-shaped output of the single synthesis call.

    Everything here is judgment or selection; every mechanical field of the
    published report is derived by :func:`assemble_report_draft`.
    """

    verdict_level: VerdictLevel
    threat_type: ThreatType
    verdict_summary: str = Field(min_length=1)
    threat_scenarios: list[str] = Field(default_factory=list)
    verdict_refs: list[str] = Field(default_factory=list)
    contradicting_refs: list[str] = Field(default_factory=list)
    units: list[JudgmentUnit] = Field(default_factory=list)
    confirmed_relations: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


@dataclass
class _ActivityFacts:
    host_ref: str | None
    observed_at: Any
    activity_type: str | None
    operation: str | None


class PointerCatalog:
    """Bidirectional map between short citation pointers and canonical IDs.

    Pointers are minted deterministically from the same whitelist the
    grounding validator enforces, so a resolved pointer can never cite an
    unauthorized object. Resolution also accepts exact canonical IDs — the
    tail ``query_results`` in the synthesis input still carries them, and a
    model quoting one verbatim is correct, not wrong.
    """

    def __init__(
        self,
        entries: dict[str, tuple[str, str]],  # pointer -> (canonical_id, kind)
        resolver: dict[str, str],  # pointer (any case) / canonical id -> canonical id
        activity_facts: dict[str, _ActivityFacts],
        resolved_relations: set[str],
        candidate_relations: set[str],
        index_block: dict[str, Any],
    ):
        self._entries = entries
        self._resolver = resolver
        self.activity_facts = activity_facts
        self.resolved_relations = resolved_relations
        self.candidate_relations = candidate_relations
        self._index_block = index_block

    @classmethod
    def build(cls, state: InvestigationState) -> "PointerCatalog":
        ledger = state.tool_ledger

        def facts_for(activity) -> _ActivityFacts:
            return _ActivityFacts(
                host_ref=getattr(activity, "host_ref", None),
                observed_at=getattr(activity, "observed_at", None),
                activity_type=getattr(activity, "activity_type", None),
                operation=getattr(activity, "operation", None),
            )

        activity_ids = sorted(set(ledger.authorized_activity_refs))
        activity_facts: dict[str, _ActivityFacts] = {}
        summaries: list[dict[str, Any]] = []
        for result in ledger.query_results:
            for activity in result.activities:
                if activity.activity_id in activity_facts:
                    continue
                activity_facts[activity.activity_id] = facts_for(activity)
        evidence_ids = sorted(
            {
                item.evidence_id
                for result in ledger.query_results
                for item in result.evidence_references
            }
        )
        resolved = set(resolved_relation_ids(state))
        candidates = set(candidate_relation_ids(state))
        entity_ids = sorted(
            {
                result.identity.entity_id
                for result in ledger.entity_results
                if result.identity is not None
            }
        )
        query_ids = sorted(executed_query_ids(state))

        def numbered(prefix: str, ids: list[str]) -> list[tuple[str, str]]:
            return [(f"{prefix}{position:03d}", value) for position, value in enumerate(ids, start=1)]

        entries: dict[str, tuple[str, str]] = {}

        def register(pairs: list[tuple[str, str]], kind: str) -> None:
            for pointer, value in pairs:
                entries[pointer] = (value, kind)

        register(numbered("a", activity_ids), "activity")
        register(numbered("e", evidence_ids), "evidence")
        register(numbered("r", sorted(resolved)), "relation_resolved")
        register(numbered("c", sorted(candidates)), "relation_candidate")
        register(numbered("x", entity_ids), "entity")
        register(numbered("q", query_ids), "query")

        # One resolver for both citation forms: pointers (case-insensitive —
        # they are short tokens the model retypes) and exact canonical IDs
        # (case-sensitive — they are copied verbatim from query_results).
        # Canonical IDs win on the (practically impossible) collision.
        resolver: dict[str, str] = {}
        for pointer, (value, _kind) in entries.items():
            resolver.setdefault(pointer, value)
            resolver.setdefault(pointer.lower(), value)
        for value in (*activity_ids, *evidence_ids, *resolved, *candidates, *entity_ids, *query_ids):
            resolver[value] = value
        pointer_of = {value: pointer for pointer, (value, _kind) in entries.items()}

        evidence_pairs = numbered("e", evidence_ids)
        resolved_pairs = numbered("r", sorted(resolved))
        candidate_pairs = numbered("c", sorted(candidates))
        entity_pairs = numbered("x", entity_ids)
        query_pairs = numbered("q", query_ids)
        index_block = {
            "how_to_cite": (
                "refs/confirmed_relations 只能使用本目录的短编号（如 a003、e001、r002、q001），"
                "或目录中列出的完整 ID。目录之外的引用会被装配器丢弃并记录为 limitation。"
                "r=已确认关系，c=候选关系：候选关系只能在陈述中作为线索，列入 confirmed_relations 会被降级剔除。"
                "q=本次运行执行过的查询，用于空结果/否定结论的引用。"
            ),
            "activities": [
                {
                    "ptr": pointer_of.get(activity_id),
                    "activity_id": activity_id,
                    "type": facts.activity_type,
                    "operation": facts.operation,
                    "host": facts.host_ref,
                    "observed_at": facts.observed_at.isoformat()
                    if facts.observed_at is not None
                    else None,
                }
                for activity_id in activity_ids
                if (facts := activity_facts.get(activity_id)) is not None
            ],
            "evidence": [{"ptr": p, "evidence_id": v} for p, v in evidence_pairs],
            "relations_resolved": [{"ptr": p, "relation_id": v} for p, v in resolved_pairs],
            "relations_candidate": [{"ptr": p, "relation_id": v} for p, v in candidate_pairs],
            "entities": [{"ptr": p, "entity_id": v} for p, v in entity_pairs],
            "queries": [{"ptr": p, "query_id": v} for p, v in query_pairs],
        }
        return cls(entries, resolver, activity_facts, resolved, candidates, index_block)

    def resolve(self, refs: list[str]) -> tuple[list[str], list[str]]:
        """Return ``(resolved canonical IDs, rejected refs)``, order preserved."""

        resolved: list[str] = []
        rejected: list[str] = []
        seen: set[str] = set()
        for ref in refs:
            cleaned = str(ref).strip()
            canonical_id = self._resolver.get(cleaned) or self._resolver.get(cleaned.lower())
            if canonical_id is None:
                rejected.append(cleaned)
            elif canonical_id not in seen:
                seen.add(canonical_id)
                resolved.append(canonical_id)
        return resolved, rejected

    def index(self) -> dict[str, Any]:
        return self._index_block


@dataclass
class AssemblyNotes:
    dropped_refs: list[str] = field(default_factory=list)
    downgraded_relations: list[str] = field(default_factory=list)


def assemble_report_draft(
    state: InvestigationState,
    judgment: InvestigationJudgment,
    catalog: PointerCatalog,
) -> tuple[ReportDraft, AssemblyNotes]:
    """Deterministically turn one judgment into a publishable ``ReportDraft``.

    Every mechanical field is computed from the ledger, never taken from the
    model. Deletions and downgrades performed here are recorded as
    limitations; nothing natural-language is ever generated or rewritten.
    """

    notes = AssemblyNotes()
    sections: dict[str, list[Any]] = {name: [] for name in _SECTION_PREFIX}
    cited_activity_ids: list[str] = []
    supporting_union: list[str] = []
    seen_supporting: set[str] = set()

    # 校验器的不对称规则：陈述层可引用查询（否定结论），结论层与报告级
    # 引用清单只接受活动/证据/关系/实体。装配时把查询引用留在陈述层，
    # 结论层的查询引用过滤掉并记录——可追溯性由反证陈述承担。
    from .report_validation import authorized_evidence_refs

    authorized_refs = authorized_evidence_refs(state)

    def split_query_refs(refs: list[str]) -> tuple[list[str], list[str]]:
        kept = [ref for ref in refs if ref in authorized_refs]
        moved = [ref for ref in refs if ref not in authorized_refs]
        return kept, moved

    def resolve_into(refs: list[str]) -> list[str]:
        resolved, rejected = catalog.resolve(refs)
        notes.dropped_refs.extend(rejected)
        for canonical_id in resolved:
            if canonical_id in catalog.activity_facts:
                cited_activity_ids.append(canonical_id)
        return resolved

    def add_supporting(resolved: list[str]) -> None:
        for canonical_id in resolved:
            if canonical_id in authorized_refs and canonical_id not in seen_supporting:
                seen_supporting.add(canonical_id)
                supporting_union.append(canonical_id)

    for unit in judgment.units:
        resolved, rejected = catalog.resolve(unit.refs)
        notes.dropped_refs.extend(rejected)
        for canonical_id in resolved:
            if canonical_id in catalog.activity_facts:
                cited_activity_ids.append(canonical_id)
        prefix = _SECTION_PREFIX[unit.section]
        position = len(sections[unit.section]) + 1
        unit_limitations = list(unit.limitations)
        if rejected:
            # Transparency for every deterministic deletion — the reader can
            # always see what the assembler dropped and why.
            unit_limitations.append(f"dropped_refs:{','.join(rejected)}")
        if not resolved and unit.refs:
            unit_limitations.append("unit_refs_all_dropped")
        sections[unit.section].append(
            {
                "statement_id": f"{prefix}-{position:02d}",
                "text": unit.text,
                "supporting_refs": resolved,
                "limitations": unit_limitations,
            }
        )
        if unit.section != "counter_evidence":
            add_supporting(resolved)

    verdict_supporting_resolved = resolve_into(judgment.verdict_refs)
    verdict_contradicting_resolved = resolve_into(judgment.contradicting_refs)
    verdict_supporting, moved_supporting = split_query_refs(verdict_supporting_resolved)
    verdict_contradicting, moved_contradicting = split_query_refs(verdict_contradicting_resolved)
    if moved_supporting:
        notes.dropped_refs.extend(moved_supporting)
    if moved_contradicting:
        # 查询引用留在陈述层（反证陈述里本就引用同一批查询），结论层不放
        notes.dropped_refs.extend(moved_contradicting)
    add_supporting(verdict_supporting)

    # confirmed_relations: resolved only; candidates are downgraded out with
    # a recorded limitation (the validator would reject them anyway — here
    # the downgrade is deterministic instead of a repair round-trip).
    confirmed: list[str] = []
    resolved_relations, rejected_relations = catalog.resolve(judgment.confirmed_relations)
    for canonical_id in resolved_relations:
        if canonical_id in catalog.candidate_relations:
            notes.downgraded_relations.append(canonical_id)
        else:
            confirmed.append(canonical_id)
    notes.dropped_refs.extend(rejected_relations)

    hosts: list[str] = []
    for activity_id in cited_activity_ids:
        facts = catalog.activity_facts.get(activity_id)
        host = facts.host_ref if facts else None
        if host and host not in hosts:
            hosts.append(host)
    if not hosts:
        hosts = list(state.scope.host_ids)

    observed = [
        catalog.activity_facts[activity_id].observed_at
        for activity_id in cited_activity_ids
        if catalog.activity_facts.get(activity_id) is not None
        and catalog.activity_facts[activity_id].observed_at is not None
    ]
    scope_start = state.scope.start_time
    scope_end = state.scope.end_time
    asserted_start = min(observed) if observed else scope_start
    asserted_end = max(observed) if observed else scope_end
    if asserted_start is not None and scope_start is not None and asserted_start < scope_start:
        asserted_start = scope_start
    if asserted_end is not None and scope_end is not None and asserted_end > scope_end:
        asserted_end = scope_end

    limitations = list(judgment.limitations)
    limitations.extend(f"candidate_relation_not_confirmed:{rid}" for rid in notes.downgraded_relations)

    draft = ReportDraft(
        verdict=CandidateVerdict(
            level=judgment.verdict_level,
            threat_type=judgment.threat_type,
            summary=judgment.verdict_summary,
            supporting_refs=verdict_supporting,
            contradicting_refs=verdict_contradicting,
            limitations=[],
        ),
        threat_scenarios=list(judgment.threat_scenarios),
        executive_summary=judgment.verdict_summary,
        current_situation=sections["current_situation"],
        affected_scope=sections["affected_scope"],
        key_evidence=sections["key_evidence"],
        supporting_evidence_refs=supporting_union,
        counter_evidence=sections["counter_evidence"],
        unresolved_questions=list(judgment.unresolved_questions),
        query_boundary_refs=sorted(executed_query_ids(state)),
        asserted_host_refs=hosts,
        asserted_start=asserted_start,
        asserted_end=asserted_end,
        confirmed_relation_refs=confirmed,
        limitations=limitations,
    )
    return draft, notes


def apply_assembly_backstops(
    state: InvestigationState,
    draft: ReportDraft,
    issues: list[ReportValidationIssue],
) -> tuple[ReportDraft, bool]:
    """Tier-1 repair: deterministic fixes for mechanical validation codes.

    Ironclad rule: this function may refill, clamp, strip or drop — it must
    never generate or alter natural-language content. Post-assembly these
    codes should be structurally impossible; the backstop exists so that any
    residual drift (e.g. a schema change reintroducing a model-filled field)
    is corrected without a model round-trip.
    """

    codes = {issue.code for issue in issues}
    update: dict[str, Any] = {}
    changed = False

    if "query_boundary_not_executed" in codes:
        correct = sorted(executed_query_ids(state))
        if draft.query_boundary_refs != correct:
            update["query_boundary_refs"] = correct
            changed = True
    if "host_assertion_out_of_scope" in codes:
        inside = [host for host in draft.asserted_host_refs if host in set(state.scope.host_ids)]
        if inside != draft.asserted_host_refs:
            update["asserted_host_refs"] = inside or list(state.scope.host_ids)
            changed = True
    if "time_assertion_out_of_scope" in codes:
        start, end = draft.asserted_start, draft.asserted_end
        if start is not None and state.scope.start_time is not None and start < state.scope.start_time:
            start, changed = state.scope.start_time, True
        if end is not None and state.scope.end_time is not None and end > state.scope.end_time:
            end, changed = state.scope.end_time, True
        update["asserted_start"], update["asserted_end"] = start, end
    if "relation_not_confirmed" in codes:
        candidates = set(candidate_relation_ids(state))
        kept = [ref for ref in draft.confirmed_relation_refs if ref not in candidates]
        if kept != draft.confirmed_relation_refs:
            update["confirmed_relation_refs"] = kept
            changed = True

    if {"unknown_evidence_ref", "evidence_ref_out_of_scope"} & codes:
        forbidden = known_out_of_scope_refs(state)
        # 只修问题点名的位置，绝不动其它字段：陈述层的查询引用是合法的
        # （否定结论的正当引用方式），全局连根拔会把小瑕疵放大成整份
        # 报告失去支撑——这正是 r10 全量兑底的放大器。
        verdict_update: dict[str, list[str]] = {}
        update.setdefault("verdict", draft.verdict)
        for issue in issues:
            if issue.code not in {"unknown_evidence_ref", "evidence_ref_out_of_scope"}:
                continue
            bad = set(issue.invalid_refs) | forbidden
            location = issue.location
            if location == "verdict.supporting_refs":
                verdict_update["supporting_refs"] = [
                    ref for ref in draft.verdict.supporting_refs if ref not in bad
                ]
            elif location == "verdict.contradicting_refs":
                verdict_update["contradicting_refs"] = [
                    ref for ref in draft.verdict.contradicting_refs if ref not in bad
                ]
            elif location == "supporting_evidence_refs":
                update["supporting_evidence_refs"] = [
                    ref for ref in draft.supporting_evidence_refs if ref not in bad
                ]
            elif location == "confirmed_relation_refs":
                update["confirmed_relation_refs"] = [
                    ref for ref in update.get(
                        "confirmed_relation_refs", draft.confirmed_relation_refs
                    )
                    if ref not in bad
                ]
            elif ".supporting_refs" in location:
                section, _, stmt_id = location.partition("[")
                stmt_id = stmt_id.split("]")[0]
                stripped = [
                    statement.model_copy(update={
                        "supporting_refs": [
                            ref for ref in statement.supporting_refs if ref not in bad
                        ]
                    })
                    if statement.statement_id == stmt_id
                    else statement
                    for statement in getattr(draft, section, []) or []
                ]
                update[section] = stripped
        if verdict_update:
            update["verdict"] = draft.verdict.model_copy(update=verdict_update)
        changed = True

    if not changed:
        return draft, False
    return draft.model_copy(update=update), True


SYNTHESIS_EXTRA_INSTRUCTIONS = [
    "你只输出判断与选择：结论、陈述文本、场景命名、存疑；不要转录任何机械字段（编号、时间戳、主机、查询清单）——系统会从台账装配",
    "refs 一律使用 evidence_catalog 中的短编号或完整 ID；无法解析的引用会被丢弃并记录",
    "每条实质性单元（current_situation/affected_scope/key_evidence/counter_evidence）至少给出一个引用；无引用的看法写进 unresolved_questions 或 limitations",
    "confirmed_relations 只接受已确认关系（r 编号）；候选关系（c 编号）只能作为线索出现在陈述里",
]


class AssembledReportComposer:
    """Judgment synthesis + minimal-edit re-judgment over the small schema.

    Holds a legacy :class:`StructuredReportComposer` for the degradation
    path: if the judgment call cannot produce a valid object, the pipeline
    falls back to the untouched legacy compose/rejudge flow.
    """

    pipeline = "assembled"

    def __init__(
        self,
        model: Any,
        event_sink: Callable | None = None,
        *,
        tenant_id: str = "default",
        memory_store: MemoryStore | None = None,
    ):
        self.legacy = StructuredReportComposer(
            model, event_sink, tenant_id=tenant_id, memory_store=memory_store
        )
        self.model_name = self.legacy.model_name
        self.event_sink = self.legacy.event_sink
        self.tenant_id = tenant_id
        self.memory_store = memory_store
        if structured_output_method(model) == "json_mode":
            self.structured_model = model.with_structured_output(
                InvestigationJudgment, method="json_mode"
            )
        else:
            self.structured_model = forced_structured(model, InvestigationJudgment)
        schema = json.dumps(InvestigationJudgment.model_json_schema(), ensure_ascii=False)
        self.synthesis_system_prompt = (
            "你是未知文件安全调查的结案研判模型。调查已经结束，你只做一次判断性总结："
            "最终结论、关键依据、反证、存疑。不要罗列证据原文，不要输出编号/时间/主机等台账信息。"
            "不得把查询空结果直接解释为行为未发生；不得把 candidate 关系写成已确认；"
            "跨主机线索只写进 unresolved_questions 或 limitations。"
            "最终威胁判断和数据充分性由你负责。"
            "只输出符合下列 InvestigationJudgment JSON Schema 的 JSON 对象，不得增加字段：" + schema
        )
        self.rejudge_system_prompt = (
            "你是未知文件安全调查的结案研判模型。上一版结案判断经系统装配与接地校验后存在问题。"
            "规则：只修改与问题相关的单元，未涉及的单元原样保留；引用只能使用目录中的短编号或完整 ID；"
            "你被明确允许修改、降低或完全放弃原有结论，包括改为 insufficient_evidence。"
            "只输出符合 InvestigationJudgment JSON Schema 的完整 JSON 对象：" + schema
        )

    # -- assembled pipeline API ------------------------------------------------

    def synthesize(self, state: InvestigationState, catalog: PointerCatalog) -> InvestigationJudgment:
        context = report_context(state, memory_store=self.memory_store)
        context["evidence_catalog"] = catalog.index()
        context["instructions"] = [*context["instructions"], *SYNTHESIS_EXTRA_INSTRUCTIONS]
        return self._generate(
            self.synthesis_system_prompt,
            json.dumps(context, ensure_ascii=False),
            call="synthesize",
        )

    def rejudge_judgment(
        self,
        state: InvestigationState,
        judgment: InvestigationJudgment,
        catalog: PointerCatalog,
        issues: list[ReportValidationIssue],
        *,
        attempt: int,
    ) -> InvestigationJudgment:
        instruction = json.dumps({
            "task": "修正结案判断中未通过接地校验的单元，输出完整 InvestigationJudgment",
            "attempt": attempt,
            "previous_judgment": judgment.model_dump(mode="json"),
            "validation_issues": [
                {"code": issue.code, "location": issue.location, "invalid_refs": issue.invalid_refs}
                for issue in issues
            ],
            "citation_catalog": catalog.index(),
        }, ensure_ascii=False)
        return self._generate(self.rejudge_system_prompt, instruction, call="rejudge_judgment")

    # -- legacy passthrough (degradation path) ---------------------------------

    def compose_draft(self, state: InvestigationState) -> ReportDraft:
        return self.legacy.compose_draft(state)

    def rejudge(
        self,
        state: InvestigationState,
        previous_draft: ReportDraft,
        issues: list[ReportValidationIssue],
        *,
        attempt: int,
    ) -> ReportDraft:
        return self.legacy.rejudge(state, previous_draft, issues, attempt=attempt)

    # -- shared structured-call machinery --------------------------------------

    def _generate(self, system_prompt: str, instruction: str, *, call: str) -> InvestigationJudgment:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": instruction},
        ]

        def invoke_once() -> InvestigationJudgment:
            return InvestigationJudgment.model_validate(self.structured_model.invoke(messages))

        def build_feedback(_attempt: int, error: Exception):
            return {
                "role": "user",
                "content": (
                    "The previous output was not valid InvestigationJudgment JSON. Return only a "
                    "complete JSON object matching the schema, without truncation or extra fields. "
                    f"Parse error: {str(error)[:800]}"
                ),
            }

        def on_attempt(attempt: int) -> None:
            self.event_sink("model_input", "结案研判模型输入", {
                "phase": "judgment_report",
                "call": call,
                "attempt": attempt,
            })

        def on_output(_attempt: int, output: InvestigationJudgment) -> None:
            self.event_sink("model_output", "结案研判模型输出", {
                "phase": "judgment_report",
                "call": call,
                "output": output.model_dump(mode="json"),
            })

        def on_failure(attempt: int, error: Exception, kind: str) -> None:
            self.event_sink(
                "model_output",
                "结案研判输出校验失败" if kind == "parse" else "结案研判模型调用失败",
                {
                    "phase": "judgment_report",
                    "call": call,
                    "attempt": attempt,
                    "error_type": type(error).__name__,
                    "error_message": str(error),
                },
            )

        return invoke_llm(
            invoke_once,
            messages=messages,
            build_feedback=build_feedback,
            on_attempt=on_attempt,
            on_output=on_output,
            on_failure=on_failure,
            parse_max_attempts=3,
        )


def publish_report_via_assembly(
    state: InvestigationState,
    composer: Any,
    *,
    validator: ReportGroundingValidator | None = None,
    fallback_builder: DeterministicFallbackBuilder | None = None,
    publisher: ReportPublisher | None = None,
    tenant_id: str = "default",
    run_id: str = "primary",
) -> Any:
    """Assembled pipeline: synthesize -> assemble -> tiered repair -> publish.

    Returns ``None`` when the judgment call exhausts its parse budget — the
    caller then falls back to the legacy compose/rejudge path, so this
    optimization can never lose a run.
    """

    from .evidence_gate import gate_verdict

    event_sink: Callable = (
        getattr(composer, "event_sink", None)
        # The demo wiring wraps composers in an observable whose sink is
        # ``emit``; without this fallback the assembly/repair narration
        # (dropped refs, downgrade counts, tier timings) silently vanishes.
        or getattr(composer, "emit", None)
        or (lambda *_args, **_kwargs: None)
    )
    validator = validator or ReportGroundingValidator()
    fallback_builder = fallback_builder or DeterministicFallbackBuilder()
    publisher = publisher or ReportPublisher(
        tenant_id=tenant_id, run_id=run_id,
        model_name=str(getattr(composer, "model_name", "unknown")),
    )

    catalog = PointerCatalog.build(state)
    started = time.perf_counter()
    try:
        judgment = composer.synthesize(state, catalog)
    except Exception as error:
        event_sink("repair", "结案研判调用失败，降级为整份报告路径", {
            "node": "compose",
            "error_type": type(error).__name__,
            "error_message": str(error)[:500],
        })
        return None

    draft, notes = assemble_report_draft(state, judgment, catalog)
    event_sink("thinking", "报告骨架装配完成（代码填充机械字段）", {
        "node": "compose",
        "units": len(judgment.units),
        "dropped_refs": notes.dropped_refs,
        "downgraded_relations": notes.downgraded_relations,
        # 每条陈述的解析后引用——与接地校验的输入完全一致，排查对账用
        "statements": [
            {"id": statement.statement_id, "refs": statement.supporting_refs}
            for section in _SECTION_PREFIX
            for statement in getattr(draft, section)
        ],
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
    })

    def emit_issues(tag: str, issue_list: list[ReportValidationIssue], draft: ReportDraft | None = None) -> None:
        if not issue_list:
            return
        from .report_validation import authorized_evidence_refs, executed_query_ids
        authorized = authorized_evidence_refs(state)
        queries = executed_query_ids(state)
        detail = []
        for issue in issue_list:
            entry = {
                "code": issue.code,
                "location": issue.location,
                "invalid_refs": issue.invalid_refs,
                "message": issue.message[:200],
            }
            if draft is not None and issue.code == "statement_without_support":
                # 定位出问题的陈述，探测其每个引用在两个合法集合里的成员关系——
                # 兜底定位专用：引用明明解析成功却被判无效时，这里给出直接证据
                section, _, stmt_id = issue.location.partition("[")
                stmt_id = stmt_id.split("]")[0]
                for statement in getattr(draft, section, []) or []:
                    if statement.statement_id == stmt_id:
                        entry["refs"] = statement.supporting_refs
                        entry["membership"] = {
                            ref: {
                                "authorized": ref in authorized,
                                "query": ref in queries,
                            }
                            for ref in statement.supporting_refs
                        }
                        break
            detail.append(entry)
        event_sink("validation", f"报告接地校验未通过（{tag}）", {
            "node": "gate",
            "authorized_size": len(authorized),
            "queries_size": len(queries),
            "issues": detail,
        })

    def validate_and_backstop(current: ReportDraft) -> tuple[ReportDraft, list[ReportValidationIssue]]:
        issues = validator.validate(state, current)
        emit_issues(f"装配后首轮 {len(issues)} 项", issues, current)
        if not issues:
            return current, issues
        current, changed = apply_assembly_backstops(state, current, issues)
        if changed:
            issues = validator.validate(state, current)
            emit_issues("backstop 后", issues, current)
        return current, issues

    draft, issues = validate_and_backstop(draft)
    attempts = 0
    while issues and attempts < state.budget.max_report_rejudgments:
        attempts += 1
        previous_codes = sorted({issue.code for issue in issues})
        rejudge_started = time.perf_counter()
        try:
            judgment = composer.rejudge_judgment(state, judgment, catalog, issues, attempt=attempts)
        except Exception as error:
            event_sink("repair", "结案判断重判失败，转入兜底发布", {
                "node": "gate",
                "attempt": attempts,
                "error_type": type(error).__name__,
                "error_message": str(error)[:500],
                "issue_codes": previous_codes,
                "duration_ms": round((time.perf_counter() - rejudge_started) * 1000, 3),
            })
            break
        draft, notes = assemble_report_draft(state, judgment, catalog)
        draft, issues = validate_and_backstop(draft)
        event_sink("repair", f"第 {attempts} 次结案判断单元级重判完成", {
            "node": "gate",
            "attempt": attempts,
            "previous_issue_codes": previous_codes,
            "issue_codes": sorted({issue.code for issue in issues}),
            "issue_locations": [issue.location for issue in issues],
            "issue_detail": [
                {"code": issue.code, "location": issue.location, "invalid_refs": issue.invalid_refs}
                for issue in issues
            ],
            "duration_ms": round((time.perf_counter() - rejudge_started) * 1000, 3),
        })
    state.budget.report_rejudgments_used = attempts

    if not issues:
        gated_verdict = gate_verdict(state, draft.verdict)
        draft = draft.model_copy(update={"verdict": gated_verdict})
        issues = validator.validate(state, draft)

    if issues:
        state.report_validation_errors = [
            f"{issue.code}@{issue.location}" for issue in issues
        ]
        fallback_draft = fallback_builder.build_draft(state, issues)
        return publisher.publish(state, fallback_draft, publication_status="fallback")
    state.report_validation_errors = []
    return publisher.publish(state, draft, publication_status="grounded")


def assembled_pipeline_supported(composer: Any) -> bool:
    return getattr(composer, "pipeline", "legacy") == "assembled"


__all__ = [
    "AssemblyNotes",
    "AssembledReportComposer",
    "InvestigationJudgment",
    "JudgmentUnit",
    "PointerCatalog",
    "apply_assembly_backstops",
    "assemble_report_draft",
    "assembled_pipeline_supported",
    "publish_report_via_assembly",
]
