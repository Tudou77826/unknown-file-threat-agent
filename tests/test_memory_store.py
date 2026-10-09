"""Unit tests for the run-scoped archive MemoryStore.

Gates from the archive/recall design (v4 §4.1):

- one archive call = one interval block, handles increment ``arc-{k}``;
- the ID -> block index is exact-address only: first archive of a record
  wins, unknown IDs return ``None`` (never fabricated);
- ``card_index`` is the compact probe entry map (handle / summary / span /
  ID inventory), aggregating IDs across rounds without duplicates.
"""

from __future__ import annotations

from threat_agent.judgment.application.memory_store import MemoryStore


def _call(tool: str, ids: dict[str, list[str]]) -> dict:
    return {"tool": tool, "args_digest": "", "args": {}, "returned": 1,
            "ids": ids, "negative": False, "error": None}


def _record_block(store: MemoryStore, *, summary: str, span: tuple[int, int],
                  rounds: list[dict], records: dict) -> str:
    return store.record_archive(
        summary=summary,
        round_span=span,
        rounds=rounds,
        snapshots=[{"type": "ai", "content": f"round {span[0]}"}],
        records=records,
    )


def test_handles_increment_and_blocks_are_addressable():
    store = MemoryStore()
    first = _record_block(
        store, summary="查证了进程链", span=(1, 2),
        rounds=[{"round": 1, "thinking": "t1", "tool_calls": [
            _call("query_process_activities", {"activities": ["act-1"]})]}],
        records={"act-1": {"activity_id": "act-1", "executable": "/tmp/a"}},
    )
    second = _record_block(
        store, summary="查证了外连", span=(3, 4),
        rounds=[{"round": 3, "thinking": "t3", "tool_calls": [
            _call("query_network_activities", {"activities": ["act-2"]})]}],
        records={"act-2": {"activity_id": "act-2"}},
    )
    assert (first, second) == ("arc-1", "arc-2")
    assert store.handles() == ["arc-1", "arc-2"]
    block = store.get_archive("arc-1")
    assert block is not None
    assert block["summary"] == "查证了进程链"
    assert block["round_span"] == [1, 2]
    assert store.get_archive("arc-9") is None


def test_id_index_is_exact_address_and_first_archive_wins():
    store = MemoryStore()
    _record_block(
        store, summary="第一段", span=(1, 2), rounds=[],
        records={"act-1": {"activity_id": "act-1", "first": True}},
    )
    _record_block(
        store, summary="第二段", span=(3, 4), rounds=[],
        records={"act-1": {"activity_id": "act-1", "first": False},
                 "ev-2": {"evidence_id": "ev-2"}},
    )
    raw = store.get_raw("act-1")
    assert raw is not None and raw["archive_id"] == "arc-1"
    assert raw["raw"]["first"] is True
    assert store.get_raw("ev-2")["archive_id"] == "arc-2"
    assert store.get_raw("act-404") is None


def test_card_index_aggregates_ids_across_rounds_without_duplicates():
    store = MemoryStore()
    _record_block(
        store, summary="进程与外连", span=(1, 4),
        rounds=[
            {"round": 1, "thinking": "t1", "tool_calls": [
                _call("query_process_activities",
                      {"activities": ["act-1", "act-2"], "queries": ["q-1"]})]},
            {"round": 2, "thinking": "t2", "tool_calls": [
                _call("query_network_activities",
                      {"activities": ["act-2", "act-3"], "evidence": ["ev-1"]})]},
        ],
        records={},
    )
    cards = store.card_index()
    assert len(cards) == 1
    card = cards[0]
    assert card["archive_id"] == "arc-1"
    assert card["summary"] == "进程与外连"
    assert card["round_span"] == [1, 4]
    assert card["ids"]["activities"] == ["act-1", "act-2", "act-3"]
    assert card["ids"]["evidence"] == ["ev-1"]
    assert card["ids"]["queries"] == ["q-1"]


def test_stats_count_archives_ids_and_rounds():
    store = MemoryStore()
    _record_block(
        store, summary="s1", span=(1, 2),
        rounds=[{"round": 1, "thinking": "", "tool_calls": []},
                {"round": 2, "thinking": "", "tool_calls": []}],
        records={"act-1": {}},
    )
    assert store.stats() == {"archives": 1, "indexed_ids": 1, "rounds_archived": 2}
