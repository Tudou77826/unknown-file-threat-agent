"""Variant derivation: same scenario, different observables, shared truth.

A derived variant substitutes ``{{param}}`` placeholders in the replay and in
the case's non-truth fields. Ground truth is copied verbatim — that is the
whole point: variants inherit the exam answer, never re-author it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._base import StrictModel
from .case_model import TestCase, VariantSpec
from .replay import (
    ReplayBundle,
    find_unresolved_placeholders,
    substitute,
    validate_canonical_event,
)


class DerivedCase(StrictModel):
    """A materialized case view, safe to feed the AI-side pipeline."""

    case: TestCase
    input_record: dict[str, Any]
    events: list[dict[str, Any]]
    coverage: dict[str, Any] | None = None


@dataclass(slots=True)
class DerivationResult:
    derived: DerivedCase
    variant_id: str
    parameters: dict[str, str]


def _substituted_case(case: TestCase, parameters: dict[str, str]) -> TestCase:
    payload = case.model_dump()
    truth = payload["ground_truth"]
    payload = substitute(payload, parameters)
    # Ground truth is never parameterized — variants share it verbatim.
    payload["ground_truth"] = truth
    payload["case_id"] = case.case_id  # identity substituted separately
    return TestCase.model_validate(payload)


def materialize_default(bundle: ReplayBundle) -> DerivedCase:
    """The base view: placeholders resolved with declared defaults."""

    return _materialize(bundle, bundle.case.parameters.defaults, None)


def derive_variant(bundle: ReplayBundle, spec: VariantSpec) -> DerivationResult:
    parameters = {**bundle.case.parameters.defaults, **spec.parameters}
    unknown = set(spec.parameters) - set(bundle.case.parameters.defaults)
    if unknown:
        raise ValueError(f"variant {spec.variant_id} sets unknown parameters: {sorted(unknown)}")
    derived = _materialize(bundle, parameters, spec.variant_id)
    return DerivationResult(derived=derived, variant_id=spec.variant_id, parameters=parameters)


def _materialize(
    bundle: ReplayBundle, parameters: dict[str, str], variant_id: str | None
) -> DerivedCase:
    case = _substituted_case(bundle.case, parameters)
    if variant_id is not None:
        case = case.model_copy(update={"case_id": case.variant_case_id(variant_id)})
    input_record = substitute(bundle.input_record, parameters)
    events = [substitute(event, parameters) for event in bundle.events]
    coverage = substitute(bundle.coverage, parameters) if bundle.coverage else None
    for event in events:
        validate_canonical_event(event)
    leftovers = sorted(
        set(
            find_unresolved_placeholders(input_record)
            + find_unresolved_placeholders(events)
            + (find_unresolved_placeholders(coverage) if coverage else [])
        )
    )
    if leftovers:
        raise ValueError(f"unresolved placeholders after substitution: {leftovers}")
    _check_derived_anchor(case, input_record)
    return DerivedCase(case=case, input_record=input_record, events=events, coverage=coverage)


def _check_derived_anchor(case: TestCase, input_record: dict[str, Any]) -> None:
    input_hash = str(input_record.get("File_hash") or input_record.get("file_hash") or "")
    if input_hash != case.judgment_target.file_hash:
        raise ValueError(
            f"derived anchor mismatch for {case.case_id}: case {case.judgment_target.file_hash} "
            f"vs input {input_hash} — a hash parameter must be substituted consistently"
        )
