"""Grounding validation for report drafts (Feature 14).

The validator is deterministic and self-contained: it depends only on the
investigation state (tool ledger + scope), never on models, bootstrap or
persistence. It returns typed, locatable issues; the workflow may only depend
on the stable issue codes, never on localized message text.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from ...shared import StrictModel
from ..domain.models import InvestigationState
from .report_draft import ReportDraft

ReportValidationIssueCode = Literal[
    "unknown_evidence_ref",
    "evidence_ref_out_of_scope",
    "statement_without_support",
    "verdict_without_support",
    "query_boundary_not_executed",
    "host_assertion_out_of_scope",
    "time_assertion_out_of_scope",
    "relation_not_confirmed",
]


class ReportValidationIssue(StrictModel):
    code: ReportValidationIssueCode
    location: str
    invalid_refs: list[str] = Field(default_factory=list)
    blocking: bool = True
    message: str = ""


# Statement groups whose entries make material factual assertions and must be
# supported by run evidence (activity/evidence refs) or executed query ids
# (negative findings legitimately cite the query that returned zero rows).
_MATERIAL_STATEMENT_SECTIONS = (
    ("current_situation", True),
    ("affected_scope", True),
    ("key_evidence", True),
    ("counter_evidence", True),
)


def authorized_evidence_refs(state: InvestigationState) -> set[str]:
    """Every identifier the run may legitimately cite in a report."""

    refs = set(state.tool_ledger.authorized_activity_refs)
    for result in state.tool_ledger.query_results:
        refs.update(item.evidence_id for item in result.evidence_references)
        refs.update(item.activity_id for item in result.activities)
    for result in state.tool_ledger.entity_results:
        if result.identity is not None:
            refs.add(result.identity.entity_id)
        refs.update(item.relation_id for item in result.resolved_relations)
        refs.update(item.relation_id for item in result.candidate_relations)
    return refs


def executed_query_ids(state: InvestigationState) -> set[str]:
    return {item.query_id for item in state.tool_ledger.query_results}


def resolved_relation_ids(state: InvestigationState) -> set[str]:
    return {
        item.relation_id
        for result in state.tool_ledger.entity_results
        for item in result.resolved_relations
    }


def candidate_relation_ids(state: InvestigationState) -> set[str]:
    return {
        item.relation_id
        for result in state.tool_ledger.entity_results
        for item in result.candidate_relations
    }


def known_out_of_scope_refs(state: InvestigationState) -> set[str]:
    """Objects the model has seen (as clues) but must never cite as evidence.

    Cross-host relations surface during authorized exploration as
    identifier-only clues; citing them as report evidence would assert facts
    about hosts the run never investigated.
    """

    refs: set[str] = set()
    for result in state.tool_ledger.entity_results:
        for clue in result.out_of_scope_relations:
            refs.add(clue.relation_id)
            refs.add(clue.other_endpoint_ref)
    return refs


class ReportGroundingValidator:
    """Validate that a draft's citations, statements and scope hold together."""

    def validate(self, state: InvestigationState, draft: ReportDraft) -> list[ReportValidationIssue]:
        issues: list[ReportValidationIssue] = []
        authorized = authorized_evidence_refs(state)
        forbidden = known_out_of_scope_refs(state)
        queries = executed_query_ids(state)
        statement_support_universe = authorized | queries

        issues.extend(self._check_cited_refs(
            draft, authorized, forbidden, statement_support_universe,
        ))
        issues.extend(self._check_verdict_support(draft))
        issues.extend(self._check_statement_support(draft, statement_support_universe))
        issues.extend(self._check_query_boundaries(draft, queries))
        issues.extend(self._check_scope_assertions(draft, state))
        issues.extend(self._check_relations(draft, state))
        return issues

    # -- reference existence -------------------------------------------------

    @staticmethod
    def _classify_ref(
        ref: str, authorized: set[str], forbidden: set[str]
    ) -> ReportValidationIssueCode | None:
        if ref in authorized:
            return None
        if ref in forbidden:
            return "evidence_ref_out_of_scope"
        return "unknown_evidence_ref"

    def _check_cited_refs(
        self,
        draft: ReportDraft,
        authorized: set[str],
        forbidden: set[str],
        statement_universe: set[str],
    ) -> list[ReportValidationIssue]:
        issues: list[ReportValidationIssue] = []

        def check(refs: list[str], location: str, universe: set[str]) -> None:
            unknown = [ref for ref in refs if ref not in universe]
            if not unknown:
                return
            code = self._classify_ref(unknown[0], authorized, forbidden)
            if code is not None:
                issues.append(ReportValidationIssue(
                    code=code,
                    location=location,
                    invalid_refs=sorted(set(unknown)),
                    message=f"引用未通过接地校验：{sorted(set(unknown))}",
                ))

        check(draft.verdict.supporting_refs, "verdict.supporting_refs", authorized)
        check(draft.verdict.contradicting_refs, "verdict.contradicting_refs", authorized)
        check(draft.supporting_evidence_refs, "supporting_evidence_refs", authorized)
        for section, _ in _MATERIAL_STATEMENT_SECTIONS:
            for statement in getattr(draft, section):
                check(
                    statement.supporting_refs,
                    f"{section}[{statement.statement_id}].supporting_refs",
                    statement_universe,
                )
        return issues

    # -- semantic floors ------------------------------------------------------

    @staticmethod
    def _check_verdict_support(draft: ReportDraft) -> list[ReportValidationIssue]:
        level = draft.verdict.level.value
        if level == "insufficient_evidence":
            return []
        if not draft.verdict.supporting_refs:
            return [ReportValidationIssue(
                code="verdict_without_support",
                location="verdict.supporting_refs",
                message=f"{level} 结论缺少任何支撑引用",
            )]
        return []

    @staticmethod
    def _check_statement_support(
        draft: ReportDraft, universe: set[str]
    ) -> list[ReportValidationIssue]:
        issues: list[ReportValidationIssue] = []
        for section, required in _MATERIAL_STATEMENT_SECTIONS:
            for statement in getattr(draft, section):
                valid = [ref for ref in statement.supporting_refs if ref in universe]
                if required and not valid:
                    issues.append(ReportValidationIssue(
                        code="statement_without_support",
                        location=f"{section}[{statement.statement_id}].supporting_refs",
                        invalid_refs=[statement.statement_id],
                        message=f"实质性陈述 {statement.statement_id} 没有任何有效支撑引用",
                    ))
        return issues

    # -- boundaries and relations ----------------------------------------------

    @staticmethod
    def _check_query_boundaries(
        draft: ReportDraft, queries: set[str]
    ) -> list[ReportValidationIssue]:
        unknown = sorted(set(draft.query_boundary_refs) - queries)
        if unknown:
            return [ReportValidationIssue(
                code="query_boundary_not_executed",
                location="query_boundary_refs",
                invalid_refs=unknown,
                message=f"报告引用了本次运行未执行的查询边界: {unknown}",
            )]
        return []

    @staticmethod
    def _check_scope_assertions(
        draft: ReportDraft, state: InvestigationState
    ) -> list[ReportValidationIssue]:
        issues: list[ReportValidationIssue] = []
        outside_hosts = sorted(set(draft.asserted_host_refs) - set(state.scope.host_ids))
        if outside_hosts:
            issues.append(ReportValidationIssue(
                code="host_assertion_out_of_scope",
                location="asserted_host_refs",
                invalid_refs=outside_hosts,
                message=f"报告主机断言超出授权 Scope: {outside_hosts}",
            ))
        if (
            draft.asserted_start is not None
            and state.scope.start_time is not None
            and draft.asserted_start < state.scope.start_time
        ):
            issues.append(ReportValidationIssue(
                code="time_assertion_out_of_scope",
                location="asserted_start",
                message="报告开始时间超出授权 Scope",
            ))
        if (
            draft.asserted_end is not None
            and state.scope.end_time is not None
            and draft.asserted_end > state.scope.end_time
        ):
            issues.append(ReportValidationIssue(
                code="time_assertion_out_of_scope",
                location="asserted_end",
                message="报告结束时间超出授权 Scope",
            ))
        return issues

    @staticmethod
    def _check_relations(
        draft: ReportDraft, state: InvestigationState
    ) -> list[ReportValidationIssue]:
        issues: list[ReportValidationIssue] = []
        candidates = candidate_relation_ids(state)
        resolved = resolved_relation_ids(state)
        as_confirmed = sorted(set(draft.confirmed_relation_refs) & candidates)
        if as_confirmed:
            issues.append(ReportValidationIssue(
                code="relation_not_confirmed",
                location="confirmed_relation_refs",
                invalid_refs=as_confirmed,
                message=f"候选关系不能作为确认关系发布: {as_confirmed}",
            ))
        unknown = sorted(set(draft.confirmed_relation_refs) - resolved)
        if unknown:
            issues.append(ReportValidationIssue(
                code="unknown_evidence_ref",
                location="confirmed_relation_refs",
                invalid_refs=unknown,
                message=f"报告确认了未知关系: {unknown}",
            ))
        return issues
