"""Targeted editing for structured drafts — the ``str_replace`` equivalent.

Anthropic's ``str_replace_based_edit_tool`` gives an agent BOTH ways to
produce a file: ``create`` (whole file) and ``str_replace``/``insert``
(targeted edits). Its value is not the commands themselves but the
discipline they enforce, which this module copies verbatim for structured
drafts (the JSON objects our pipelines ask models to produce):

1. exact anchors — an edit quoting an ``anchor`` is applied only if the
   current value at the path equals it, byte for byte; no fuzzy matching;
2. errors, not guesses — a path that does not resolve, an anchor that does
   not match, an out-of-range index: the edit is rejected with the actual
   current state in the receipt, never silently coerced;
3. minimal blast radius — only explicitly targeted values change; every
   other field is carried over untouched, and each edit in a batch sees the
   result of the previous one (like consecutive editor commands).

The retry layer historically had only the ``create`` equivalent (regenerate
the whole object), which is why a missing ``approval_class`` in a
seven-thousand-token proposal cost another full rewrite. Callers now mix
both: full generation first, targeted repair afterwards.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Literal, Union

from pydantic import Field

from .model import StrictModel


class DraftEdit(StrictModel):
    """One targeted edit on a structured draft.

    ``path`` walks the draft: strings index objects, integers index arrays
    (numeric strings are accepted for array steps). ``anchor`` is the
    expected current value at the path — the ``old_str`` equivalent. For
    ``set`` a null anchor means "field must be absent" (filling a missing
    field); for ``remove`` it is checked when provided.
    """

    op: Literal["set", "insert", "remove"]
    path: list[Union[str, int]] = Field(min_length=1, max_length=8)
    anchor: Any = None
    value: Any = None


class DraftEdits(StrictModel):
    """A batch of edits, applied in order — the model-facing repair output."""

    edits: list[DraftEdit] = Field(min_length=1, max_length=40)


@dataclass
class RejectedEdit:
    index: int
    reason: str
    actual: Any = None


@dataclass
class EditResult:
    draft: dict
    applied: list[int] = field(default_factory=list)
    rejected: list[RejectedEdit] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.rejected


def _step(parent: Any, step: Union[str, int], position: int) -> tuple[Any, Any]:
    """Resolve one path step against its container; raise ValueError with the
    actual state on any mismatch (rule 2: errors, not guesses)."""

    if isinstance(parent, list):
        if isinstance(step, str) and step.lstrip("-").isdigit():
            step = int(step)
        if not isinstance(step, int) or not -len(parent) <= step < len(parent):
            raise ValueError(
                f"path[{position}]={step!r} out of range for list of len {len(parent)}"
            )
        return parent[step], step
    if isinstance(parent, dict):
        if not isinstance(step, str):
            raise ValueError(f"path[{position}]={step!r} is not an object key")
        if step not in parent:
            raise ValueError(f"path[{position}]={step!r} not present")
        return parent[step], step
    raise ValueError(f"path[{position}] navigates into a scalar ({type(parent).__name__})")


def _resolve_parent(draft: dict, path: list[Union[str, int]]) -> tuple[Any, Union[str, int]]:
    current: Any = draft
    for position, step in enumerate(path[:-1]):
        current, _ = _step(current, step, position)
    return current, path[-1]


def apply_edits(draft: dict, edits: list[DraftEdit]) -> EditResult:
    """Apply edits in order on a deep copy; never mutate the input draft."""

    working = copy.deepcopy(draft)
    result = EditResult(draft=working)
    for index, edit in enumerate(edits):
        try:
            if edit.op == "set":
                parent, key = _resolve_parent(working, edit.path)
                if isinstance(parent, list):
                    current, _ = _step(parent, key, len(edit.path) - 1)
                    if edit.anchor is not None and current != edit.anchor:
                        raise ValueError(
                            f"anchor mismatch: current={json_of(current)}"
                        )
                    parent[int(key) if isinstance(key, str) else key] = edit.value
                elif isinstance(parent, dict):
                    if edit.anchor is None and key in parent:
                        raise ValueError(
                            f"field {key!r} exists (current={json_of(parent[key])}); quote it as anchor to overwrite"
                        )
                    if edit.anchor is not None:
                        if key not in parent or parent[key] != edit.anchor:
                            actual = parent.get(key, "<absent>")
                            raise ValueError(
                                f"anchor mismatch: actual={json_of(actual)}"
                            )
                    parent[key] = edit.value
                else:
                    raise ValueError("set target parent is a scalar")
            elif edit.op == "insert":
                parent, key = _resolve_parent(working, edit.path)
                if not isinstance(parent, list):
                    raise ValueError("insert target parent is not a list")
                position = int(key) if isinstance(key, str) else key
                if not 0 <= position <= len(parent):
                    raise ValueError(
                        f"insert position {position} out of range [0, {len(parent)}]"
                    )
                parent.insert(position, edit.value)
            elif edit.op == "remove":
                parent, key = _resolve_parent(working, edit.path)
                if isinstance(parent, list):
                    current, _ = _step(parent, key, len(edit.path) - 1)
                    if edit.anchor is not None and current != edit.anchor:
                        raise ValueError(f"anchor mismatch: current={json_of(current)}")
                    parent.pop(int(key) if isinstance(key, str) else key)
                elif isinstance(parent, dict):
                    if key not in parent:
                        raise ValueError(f"field {key!r} not present")
                    if edit.anchor is not None and parent[key] != edit.anchor:
                        raise ValueError(
                            f"anchor mismatch: actual={json_of(parent[key])}"
                        )
                    del parent[key]
                else:
                    raise ValueError("remove target parent is a scalar")
            else:  # pragma: no cover - schema constrains the literal
                raise ValueError(f"unknown op {edit.op!r}")
        except ValueError as error:
            result.rejected.append(RejectedEdit(index=index, reason=str(error)[:400]))
            continue
        result.applied.append(index)
    # Publish the final state even with rejections: applied edits stand,
    # rejected ones are reported so the caller can re-target them.
    result.draft = working
    return result


def json_of(value: Any) -> str:
    import json

    try:
        return json.dumps(value, ensure_ascii=False)[:200]
    except TypeError:
        return repr(value)[:200]


__all__ = ["DraftEdit", "DraftEdits", "EditResult", "RejectedEdit", "apply_edits"]
