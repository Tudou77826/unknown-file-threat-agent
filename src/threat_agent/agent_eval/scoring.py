"""Two-phase scoring (design.md §4.3): batch offline scoring over recorded
RunRecords. Zero LLM calls, zero network — a scorer reads raw artifacts from
the run workdir plus the case ground truth, nothing else. ``regrade`` is a
first-class entry: deleting the score cache and re-scoring is always safe
and cheap.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .core import Case, RunRecord, Score, Scorer


class ScoreRunner:
    def __init__(self, scorers: list[Scorer]):
        if not scorers:
            raise ValueError("ScoreRunner 需要至少一个 Scorer")
        names = [scorer.name for scorer in scorers]
        if len(set(names)) != len(names):
            raise ValueError(f"Scorer 名称重复：{names}")
        self.scorers = list(scorers)

    def score_record(self, record: RunRecord, case: Case, *, workdir: Path | None = None) -> list[Score]:
        scores: list[Score] = []
        for scorer in self.scorers:
            try:
                score = scorer.score(record, case)
            except Exception as error:  # noqa: BLE001 — 打分器故障如实记录，不中断批量
                score = Score(
                    scorer=scorer.name,
                    total=0.0,
                    passed=False,
                    notes=[f"打分器异常：{type(error).__name__}: {error}"],
                )
            scores.append(score)
        self._persist(record.run_id, scores, workdir)
        return scores

    def score_all(
        self,
        records: Iterable[tuple[RunRecord, Case]],
        *,
        workdir_of: "callable | None" = None,
    ) -> dict[str, list[Score]]:
        """Batch scoring keyed by run_id. ``workdir_of(run_id)`` optionally
        locates a run workdir for per-run score persistence."""

        out: dict[str, list[Score]] = {}
        for record, case in records:
            scores = self.score_record(record, case, workdir=workdir_of(record.run_id) if workdir_of else None)
            out[record.run_id] = scores
        return out

    # -- internals -----------------------------------------------------------

    def _persist(self, run_id: str, scores: list[Score], workdir: Path | None) -> None:
        if workdir is None:
            return
        path = Path(workdir) / "scores.json"
        path.write_text(
            json.dumps([score.model_dump() for score in scores], ensure_ascii=False, indent=1),
            encoding="utf-8",
        )


def load_scores(workdir: Path) -> list[Score]:
    """Regrade entry: read persisted scores without recomputing."""

    path = Path(workdir) / "scores.json"
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [Score.model_validate(item) for item in payload]
