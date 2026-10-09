"""Run-scoped archive memory for context archive / recall.

One ``MemoryStore`` instance lives for one investigation run (created by
``middleware_runtime``, shared by the archive middleware, the recall tools
and report assembly). It owns:

- interval snapshot blocks — one archive call's full message-interval
  record, addressed by an incrementing ``arc-{k}`` handle;
- an exact ``record_id -> block`` index over every citable identifier the
  interval produced (activity / evidence / relation / query IDs), serving
  "fetch the original by known address" only — never content retrieval.

The store is deliberately a plain data structure: it parses nothing and
guesses nothing. Facts (returned counts, ID lists, arguments digests) are
computed deterministically by the archive middleware when the block is
recorded; recall reads them back verbatim.
"""

from __future__ import annotations

from typing import Any


class MemoryStore:
    """Archive region for one run: interval blocks plus an ID address index."""

    def __init__(self) -> None:
        self._blocks: dict[str, dict[str, Any]] = {}
        # record_id -> {"archive_id": str, "record": dict}; first archive of an
        # ID wins — the earliest snapshot is the one the model saw produced.
        self._index: dict[str, dict[str, Any]] = {}

    # -- write path (called by the archive middleware) ----------------------

    def record_archive(
        self,
        *,
        summary: str,
        round_span: tuple[int, int] | list[int],
        rounds: list[dict[str, Any]],
        snapshots: list[dict[str, Any]],
        records: dict[str, Any],
    ) -> str:
        """Store one archive block and return its handle.

        ``rounds`` carries the per-round deterministic facts (thinking text,
        tool calls with arguments digests, returned counts, produced IDs);
        ``snapshots`` the serialized message interval; ``records`` the exact
        ``record_id -> original record`` mapping extracted from the original
        tool payloads (unreduced artifact preferred).
        """
        handle = f"arc-{len(self._blocks) + 1}"
        block: dict[str, Any] = {
            "archive_id": handle,
            "summary": summary,
            "round_span": [round_span[0], round_span[1]],
            "rounds": rounds,
            "snapshots": snapshots,
        }
        self._blocks[handle] = block
        for record_id, record in records.items():
            self._index.setdefault(
                record_id, {"archive_id": handle, "record": record}
            )
        return handle

    # -- read path (recall entries, probe agent, report assembly) -----------

    def get_archive(self, handle: str) -> dict[str, Any] | None:
        """Full block detail for a handle, or ``None`` when unknown."""
        return self._blocks.get(str(handle))

    def handles(self) -> list[str]:
        """Existing handles in creation order."""
        return list(self._blocks)

    def card_index(self) -> list[dict[str, Any]]:
        """Compact index of all cards — the probe agent's entry map.

        Deliberately small: handle, summary, round span and the citable ID
        inventory per card; no message content.
        """
        cards: list[dict[str, Any]] = []
        for block in self._blocks.values():
            ids: dict[str, list[str]] = {}
            for round_record in block["rounds"]:
                for call in round_record.get("tool_calls", []):
                    for kind, values in (call.get("ids") or {}).items():
                        ids.setdefault(kind, [])
                        for value in values:
                            if value not in ids[kind]:
                                ids[kind].append(value)
            cards.append(
                {
                    "archive_id": block["archive_id"],
                    "summary": block["summary"],
                    "round_span": block["round_span"],
                    "ids": ids,
                }
            )
        return cards

    def get_raw(self, record_id: str) -> dict[str, Any] | None:
        """Exact-address fetch of one original record, or ``None``."""
        entry = self._index.get(str(record_id))
        if entry is None:
            return None
        return {
            "record_id": str(record_id),
            "archive_id": entry["archive_id"],
            "raw": entry["record"],
        }

    def stats(self) -> dict[str, int]:
        """Observation counters: archive count, indexed IDs, archived rounds."""
        return {
            "archives": len(self._blocks),
            "indexed_ids": len(self._index),
            "rounds_archived": sum(
                len(block["rounds"]) for block in self._blocks.values()
            ),
        }

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        stats = self.stats()
        return (
            f"MemoryStore(archives={stats['archives']}, "
            f"ids={stats['indexed_ids']}, rounds={stats['rounds_archived']})"
        )


__all__ = ["MemoryStore"]
