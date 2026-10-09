"""Targeted draft editing (str_replace discipline) and its advisory wiring.

Covers the three ironclad rules copied from Anthropic's editor tool:
exact anchors, errors-not-guesses, minimal blast radius — plus the
planner-level repair loop that replaces full-rewrite retries.
"""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage

from threat_agent.contracts.investigation import CandidateVerdict, JudgmentResult
from threat_agent.response_advisory.application.planner import StructuredResponsePlanner
from threat_agent.response_advisory.domain.models import ResponseProposal
from threat_agent.shared.draft_editor import DraftEdit, DraftEdits, apply_edits
from threat_agent.shared.llm import forced_structured


def _edit(op: str, path: list, value=None, anchor="__unset__") -> DraftEdit:
    kwargs = {}
    if anchor != "__unset__":
        kwargs["anchor"] = anchor
    if value is not None or op in ("set", "insert"):
        kwargs["value"] = value
    return DraftEdit(op=op, path=path, **kwargs)


def _base_draft() -> dict:
    return {
        "actions": [
            {
                "action_id": "act-1",
                "action_type": "collect_more_data",
                "rationale": "补齐遥测",
                "expected_impact": "只读",
            }
        ],
        "missing_context": ["样本未取得"],
    }


# -- ironclad rule 1+3: exact anchors, minimal blast radius -------------------


def test_set_fills_missing_field_without_anchor():
    result = apply_edits(_base_draft(), [_edit("set", ["actions", 0, "approval_class"], "none")])
    assert result.ok
    assert result.draft["actions"][0]["approval_class"] == "none"
    # Untargeted fields carry over untouched.
    assert result.draft["actions"][0]["rationale"] == "补齐遥测"
    assert result.draft["missing_context"] == ["样本未取得"]


def test_set_replaces_quoted_value_only_when_anchor_matches():
    draft = _base_draft()
    good = apply_edits(draft, [_edit("set", ["actions", 0, "rationale"], "新理由", anchor="补齐遥测")])
    assert good.ok and good.draft["actions"][0]["rationale"] == "新理由"

    bad = apply_edits(draft, [_edit("set", ["actions", 0, "rationale"], "篡改", anchor="错误的当前值")])
    assert not bad.ok
    assert bad.rejected[0].index == 0
    assert "anchor mismatch" in bad.rejected[0].reason
    assert "补齐遥测" in bad.rejected[0].reason  # receipt carries the actual value
    assert draft["actions"][0]["rationale"] == "补齐遥测"


def test_set_on_existing_field_without_anchor_is_rejected():
    result = apply_edits(_base_draft(), [_edit("set", ["actions", 0, "rationale"], "绕过锚点")])
    assert not result.ok
    assert "anchor" in result.rejected[0].reason
    assert result.draft["actions"][0]["rationale"] == "补齐遥测"


# -- rule 2: errors, not guesses ----------------------------------------------


def test_path_into_missing_container_is_rejected_never_created():
    result = apply_edits(_base_draft(), [_edit("set", ["actions", 5, "approval_class"], "none")])
    assert not result.ok
    assert "out of range" in result.rejected[0].reason
    assert len(result.draft["actions"]) == 1


def test_insert_appends_full_item_and_rejects_out_of_range():
    result = apply_edits(_base_draft(), [_edit("insert", ["actions", 1], value={
        "action_id": "act-2", "action_type": "manual_review",
        "rationale": "转人工", "expected_impact": "无影响", "approval_class": "none",
    })])
    assert result.ok and len(result.draft["actions"]) == 2

    bad = apply_edits(_base_draft(), [_edit("insert", ["actions", 9], value={"x": 1})])
    assert not bad.ok and "out of range" in bad.rejected[0].reason


def test_remove_requires_anchor_match():
    draft = _base_draft()
    ok = apply_edits(draft, [_edit("remove", ["missing_context", 0], anchor="样本未取得")])
    assert ok.ok and ok.draft["missing_context"] == []

    bad = apply_edits(draft, [_edit("remove", ["missing_context", 0], anchor="别的东西")])
    assert not bad.ok and bad.draft["missing_context"] == ["样本未取得"]


def test_edits_apply_sequentially_and_input_is_never_mutated():
    original = _base_draft()
    result = apply_edits(original, [
        _edit("set", ["actions", 0, "approval_class"], "none"),
        _edit("set", ["actions", 0, "rollback_steps"], ["恢复采集"]),
        _edit("set", ["residual_risk"], ["残留风险"]),
    ])
    assert result.ok
    assert result.draft["actions"][0]["rollback_steps"] == ["恢复采集"]
    assert result.draft["residual_risk"] == ["残留风险"]
    assert "approval_class" not in original["actions"][0]  # input untouched
    assert "residual_risk" not in original


# -- planner-level repair loop ------------------------------------------------


class _QueueToolModel:
    """Serve queued tool-call args to every bound schema call in order."""

    model_name = "fake-tool-model"

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[tuple] = []

    def bind_tools(self, schemas, **_kwargs):
        outer = self

        class _Bound:
            def invoke(self, messages, config=None):
                outer.calls.append((tuple(str(m)[:400] for m in messages),))
                item = outer.responses.pop(0)
                if isinstance(item, Exception):
                    raise item
                if item == "__no_tool_call__":
                    return AIMessage(content="(prose answer)")
                return AIMessage(
                    content="",
                    tool_calls=[{"name": "tool", "args": item, "id": f"c{len(outer.calls)}"}],
                )

        return _Bound()


_BAD_PARTIAL = {
    "actions": [
        {
            "action_id": "act-1",
            "action_type": "collect_more_data",
            "target_refs": ["server-01"],
            "rationale": "证据不足先补遥测",
            "expected_impact": "只读采集，无业务影响",
        }
    ],
    "missing_context": ["样本本体未取得"],
}

_FIX_EDITS = {
    "edits": [
        {"op": "set", "path": ["actions", 0, "approval_class"], "value": "none"},
        {"op": "set", "path": ["actions", 0, "rollback_steps"], "value": []},
        {"op": "set", "path": ["actions", 0, "verification_steps"], "value": ["确认新数据可查询"]},
    ]
}


def _judgment() -> JudgmentResult:
    return JudgmentResult(
        tenant_id="default",
        case_id="case-1",
        verdict=CandidateVerdict(
            level="suspicious", threat_type="unknown", summary="证据不足"
        ),
    )


def _events_collector():
    events: list[tuple] = []
    return events, (lambda kind, message, details=None: events.append((kind, message, details)))


def test_planner_repairs_partial_draft_with_targeted_edits():
    events, sink = _events_collector()
    model = _QueueToolModel([_BAD_PARTIAL, _FIX_EDITS])
    planner = StructuredResponsePlanner(model, sink)
    proposal = planner.propose(_judgment(), None, [])
    assert isinstance(proposal, ResponseProposal)
    assert proposal.actions[0].approval_class == "none"
    assert proposal.actions[0].verification_steps == ["确认新数据可查询"]
    repair_events = [e for e in events if e[0] == "repair" and "定点修补" in e[1]]
    assert len(repair_events) == 1
    assert repair_events[0][2]["edits_applied"] == 3
    assert repair_events[0][2]["edits_rejected"] == []
    assert not any("降级" in e[1] for e in events)


def test_planner_keeps_full_retry_for_prose_failure():
    _GOOD = {
        "actions": [],
        "missing_context": ["样本未取得"],
        "residual_risk": [],
    }
    events, sink = _events_collector()
    model = _QueueToolModel(["__no_tool_call__", _GOOD])
    planner = StructuredResponsePlanner(model, sink)
    proposal = planner.propose(_judgment(), None, [])
    assert isinstance(proposal, ResponseProposal)
    assert proposal.missing_context == ["样本未取得"]
    assert not any("定点修补" in e[1] for e in events)


def test_planner_degrades_when_repair_cannot_fix():
    _WORSE_EDITS = {"edits": [{"op": "set", "path": ["actions", 0, "rationale"], "value": "x", "anchor": "不匹配"}]}
    events, sink = _events_collector()
    model = _QueueToolModel([_BAD_PARTIAL, _WORSE_EDITS, _WORSE_EDITS])
    planner = StructuredResponsePlanner(model, sink)
    with pytest.raises(RuntimeError):
        planner.propose(_judgment(), None, [])


def test_forced_structured_carries_partial_payload():
    model = _QueueToolModel([_BAD_PARTIAL])
    bound = forced_structured(model, ResponseProposal)
    with pytest.raises(Exception) as excinfo:
        bound.invoke([{"role": "user", "content": "go"}])
    payload = getattr(excinfo.value, "args_payload", "__missing__")
    assert payload == _BAD_PARTIAL
