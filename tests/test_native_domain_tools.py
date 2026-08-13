from __future__ import annotations

import json
from pathlib import Path

import pytest

from threat_agent.case_management import initialize_state
from threat_agent.data_foundation.adapters.repository import JsonlEventRepository
from threat_agent.judgment.adapters.tools import DOMAIN_TOOL_DOMAINS, ToolRegistry


ROOT = Path(__file__).resolve().parents[1]


def _setup(case_name="c2_malicious"):
    case_dir = ROOT / "cases" / case_name
    raw = json.loads((case_dir / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    return state, ToolRegistry(JsonlEventRepository(case_dir))


def test_native_tool_specs_are_fixed_and_schema_stable():
    state, registry = _setup()
    specs = registry.native_tool_specs()
    names = [name for name, _schema, _desc in specs]
    assert names == [
        "query_process_evidence",
        "query_file_evidence",
        "query_network_evidence",
        "query_persistence_evidence",
        "query_reputation_evidence",
        "analyze_evidence",
        "activate_scenario",
        "request_scope_expansion",
        "finish_investigation",
    ]
    # Domain tools share one fixed schema; schema must not depend on case state.
    first = json.dumps(specs[0][1].model_json_schema(), sort_keys=True)
    second = json.dumps(specs[1][1].model_json_schema(), sort_keys=True)
    assert first == second
    assert "gap_id" in specs[0][1].model_json_schema()["properties"]
    assert "host_id" in specs[0][1].model_json_schema()["properties"]


def test_eligible_gap_ids_maps_gaps_to_domains():
    state, registry = _setup()
    eligible = registry.eligible_gap_ids(state)
    assert eligible["process"] == ["gap-execution", "gap-process-chain", "gap-remote-command"]
    assert eligible["network"] == ["gap-network", "gap-remote-command"]
    assert eligible["persistence"] == ["gap-persistence"]
    assert eligible["reputation"] == ["gap-counter"]
    assert eligible["file"] == []


def test_resolve_domain_gap_returns_intersection_types():
    state, registry = _setup()
    assert registry.resolve_domain_gap(state, "process", "gap-execution") == frozenset({"process_exec"})
    # gap-remote-command spans network (socket_io) and process (child_process_exec).
    assert registry.resolve_domain_gap(state, "network", "gap-remote-command") == frozenset({"socket_io"})
    assert registry.resolve_domain_gap(state, "process", "gap-remote-command") == frozenset({"child_process_exec"})


def test_resolve_domain_gap_rejects_mismatched_domain():
    state, registry = _setup()
    with pytest.raises(ValueError, match="not addressable"):
        registry.resolve_domain_gap(state, "file", "gap-execution")


def test_invoke_domain_evidence_queries_and_returns_requested_types():
    state, registry = _setup()
    bundle, requested_types = registry.invoke_domain_evidence(
        state, "query_process_evidence", "gap-execution", {}
    )
    assert requested_types == frozenset({"process_exec"})
    assert {item.evidence_type for item in bundle.evidence} == {"process_exec"}


def test_domain_tool_names_match_domain_table():
    state, registry = _setup()
    assert registry.domain_tool_names() == tuple(DOMAIN_TOOL_DOMAINS)
    assert set(registry.domain_tool_names()) == set(DOMAIN_TOOL_DOMAINS.keys())
