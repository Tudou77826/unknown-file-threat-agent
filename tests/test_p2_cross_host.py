from pathlib import Path

import pytest
from langchain_core.messages import AIMessage

from threat_agent.bootstrap.cli import run_case
from threat_agent.case_management import initialize_state
from threat_agent.judgment.domain.models import ScopeRequest, VerdictLevel
from threat_agent.judgment.application.policy import PolicyError, validate_action
from threat_agent.judgment.application.planner import StructuredJudgmentPlanner
from threat_agent.data_foundation.adapters.repository import JsonlEventRepository
from threat_agent.judgment.adapters.tools import ToolRegistry

ROOT = Path(__file__).resolve().parents[1]


class _ScopeModel:
    model_name = "fake-native-model"

    def __init__(self, tool_calls):
        self.tool_calls = tool_calls

    def bind_tools(self, tools, **_kwargs):
        self.bound_tools = tools
        return self

    def invoke(self, _messages):
        return AIMessage(content="", tool_calls=self.tool_calls)


def run(name):
    return run_case(ROOT / "cases" / name)


def test_direct_transfer_login_presence_and_execution_close_cross_host_path():
    state = run("cross_host_malicious")
    assert state.verdict.level == VerdictLevel.LIKELY_MALICIOUS
    assert "server-03" in state.scope.host_ids
    assert state.scope_expansions[0].approval_status == "approved"
    assert "confirmed_lateral_file_propagation" in {f.finding_type for f in state.findings}


def test_approved_multi_host_deployment_is_counter_evidence():
    state = run("cross_host_benign_deployment")
    assert state.verdict.level == VerdictLevel.BENIGN
    assert "legitimate_multi_host_deployment" in {f.finding_type for f in state.findings}


def test_shared_c2_without_transfer_does_not_expand_or_prove_propagation():
    state = run("cross_host_shared_c2_only")
    assert state.scope.host_ids == ["shared-01"]
    assert not state.scope_expansions
    assert "shared_infrastructure_only" in {f.finding_type for f in state.findings}
    assert "confirmed_lateral_file_propagation" not in {f.finding_type for f in state.findings}


def test_approval_required_scope_does_not_read_target_host_evidence():
    state = run("cross_host_scope_denied")
    assert state.scope.host_ids == ["deny-01"]
    assert state.scope_expansions[0].approval_status == "denied"
    assert state.scope_expansions[0].approval_source == "human:cli-policy"
    assert "deny-hidden-target" not in {e.evidence_id for e in state.evidence}
    assert "confirmed_lateral_file_propagation" not in {f.finding_type for f in state.findings}


def test_policy_rejects_candidate_host_not_named_by_cited_evidence():
    case_dir = ROOT / "cases" / "cross_host_scope_denied"
    import json
    state = initialize_state(json.loads((case_dir / "input.json").read_text(encoding="utf-8")))
    repository = JsonlEventRepository(case_dir)
    registry = ToolRegistry(repository)
    bundle = repository.query("file", frozenset({"file_transfer_cross_host"}), state)
    state.evidence.extend(bundle.evidence)
    request = ScopeRequest(objective="Investigate an unrelated candidate host", requested_host_ids=["unrelated-99"], reason_evidence_refs=["deny-transfer"])
    with pytest.raises(PolicyError, match="not grounded"):
        validate_action(request, state, registry)


def test_deep_planner_can_submit_but_not_approve_grounded_scope_request():
    case_dir = ROOT / "cases" / "cross_host_scope_denied"
    import json
    state = initialize_state(json.loads((case_dir / "input.json").read_text(encoding="utf-8")))
    repository = JsonlEventRepository(case_dir)
    registry = ToolRegistry(repository)
    state.evidence.extend(registry.invoke("query_file_transfer_across_hosts", state, {}).evidence)
    planner = StructuredJudgmentPlanner(_ScopeModel([{
        "name": "request_scope_expansion",
        "args": {
            "objective": "The successful transfer directly identifies deny-02 as the minimal candidate host.",
            "requested_host_ids": ["deny-02"],
            "reason_type": "file_transfer",
            "reason_evidence_refs": ["deny-transfer"],
            "requested_domains": ["process", "file", "network"],
        },
        "id": "call-scope-1",
        "type": "tool_call",
    }]), registry)
    action = planner.plan(state)
    assert isinstance(action, ScopeRequest)
    assert action.requested_host_ids == ["deny-02"]
    assert state.scope.host_ids == ["deny-01"]
    validate_action(action, state, registry)


def test_deep_scope_proposal_is_normalized_to_evidence_refs_and_domains():
    case_dir = ROOT / "cases" / "cross_host_scope_denied"
    import json
    state = initialize_state(json.loads((case_dir / "input.json").read_text(encoding="utf-8")))
    repository = JsonlEventRepository(case_dir)
    registry = ToolRegistry(repository)
    state.evidence.extend(registry.invoke("query_file_transfer_across_hosts", state, {}).evidence)
    planner = StructuredJudgmentPlanner(_ScopeModel([{
        "name": "request_scope_expansion",
        "args": {
            "objective": "The cited transfer identifies the minimal candidate host for investigation.",
            "requested_host_ids": ["deny-02"],
            "reason_evidence_refs": ["deny-transfer", "finding-cross-host-lead-001"],
            "requested_domains": ["file", "process", "host_asset", "invented"],
        },
        "id": "call-scope-2",
        "type": "tool_call",
    }]), registry)
    action = planner.plan(state)
    assert action.reason_evidence_refs == ["deny-transfer"]
    assert action.requested_domains == ["file", "process", "reputation"]
    validate_action(action, state, registry)
