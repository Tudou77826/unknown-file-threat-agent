import json
from pathlib import Path

from threat_agent.ingestion import initialize_state


ROOT = Path(__file__).resolve().parents[1]


def test_ppt_fields_and_detail_string_are_supported():
    raw = json.loads((ROOT / "cases" / "c2_malicious" / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    file_entity = next(x for x in state.entities if x.entity_type == "file")
    assert file_entity.attributes["sha256"] == "a" * 64
    assert file_entity.attributes["path"] == "/tmp/.cache/sysupd"
    chain = next(x for x in state.evidence if x.evidence_type == "upstream_process_chain")
    assert chain.data["tree_direct_parent_to_root"][0]["processName"] == "bash"
    assert chain.data["tree_direct_parent_to_root"][1]["processName"] == "sshd"


def test_missing_anchor_is_rejected():
    try:
        initialize_state({"File_hash": "a" * 64})
    except ValueError as exc:
        assert "must provide" in str(exc)
    else:
        raise AssertionError("Invalid input was accepted")

