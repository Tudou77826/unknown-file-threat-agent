"""Feature 17: project the operational event ledger into the trajectory read
model — rounds as the narrative spine, every entry carrying its collapsible
detail and cross-links (evidence refs, knowledge consultations).

Pure projection: events in, read model out. Details are already redacted at
persistence time; nothing is re-filtered here (no silent repair paths).
"""

from __future__ import annotations

from ...contracts import (
    OperationalEvent,
    TrajectoryEntry,
    TrajectoryReadModel,
    TrajectoryRound,
)

_ROUND_KINDS = ("round",)
_NARRATIVE_KINDS = {"thinking", "decision", "verdict", "report", "response", "result", "complete", "approval"}
_MAX_SUMMARY = 160


def _entry(event: OperationalEvent) -> TrajectoryEntry:
    details = event.details or {}
    evidence_refs: list[str] = []
    for key in ("query_id", "report_id", "request_ref"):
        if details.get(key):
            evidence_refs.append(str(details[key]))
    for ref in details.get("evidence_ids") or []:
        evidence_refs.append(str(ref))
    consultation_ids = (
        [str(details["consultation_id"])] if details.get("consultation_id") else []
    )
    message = str(details.get("message") or "")
    summary = message if len(message) <= _MAX_SUMMARY else message[: _MAX_SUMMARY - 1] + "…"
    return TrajectoryEntry(
        event_id=event.event_id,
        kind=str(details.get("kind") or event.event_type),
        node=event.node,
        sequence=event.sequence,
        duration_ms=event.duration_ms,
        token_usage=dict(event.token_usage),
        retry_count=event.retry_count,
        summary=summary,
        detail=details,
        evidence_refs=evidence_refs,
        consultation_ids=consultation_ids,
    )


def build_trajectory(
    events: list[OperationalEvent], *, run_id: str, case_id: str
) -> TrajectoryReadModel:
    rounds: list[TrajectoryRound] = []
    phase_entries: list[TrajectoryEntry] = []
    pending: list[TrajectoryEntry] = []
    totals: dict[str, float] = {"duration_ms": 0.0, "retries": 0}
    token_totals: dict[str, int] = {}

    for event in events:
        details = event.details or {}
        kind = str(details.get("kind") or event.event_type)
        entry = _entry(event)
        for key, value in (event.token_usage or {}).items():
            token_totals[key] = token_totals.get(key, 0) + int(value)
        if event.duration_ms:
            totals["duration_ms"] += event.duration_ms
        totals["retries"] += event.retry_count

        if kind in _ROUND_KINDS:
            # The round marker summarizes the round that just happened: the
            # tool work buffered since the previous marker belongs to it.
            rounds.append(
                TrajectoryRound(
                    index=len(rounds) + 1,
                    observation=message_text(details),
                    entries=pending,
                )
            )
            pending = []
            continue
        if kind in ("run", "graph", "error") or kind in _NARRATIVE_KINDS:
            # Lifecycle/narrative markers stay in the phase lane.
            phase_entries.append(entry)
            continue
        pending.append(entry)

    # Work after the last round marker (e.g. report composition) attaches to
    # the final round; without any round it stays in the phase lane.
    if pending:
        if rounds:
            rounds[-1].entries.extend(pending)
        else:
            phase_entries.extend(pending)

    totals["token_usage"] = token_totals
    totals["events"] = len(events)
    return TrajectoryReadModel(
        run_id=run_id,
        case_id=case_id,
        rounds=rounds,
        phase_entries=phase_entries,
        totals=totals,
    )


def message_text(details: dict) -> str | None:
    message = details.get("observation") or details.get("message")
    return str(message) if message else None
