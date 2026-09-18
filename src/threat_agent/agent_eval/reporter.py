"""Aggregation and reporting (design.md step 02).

Pure functions over RunRecords + Scores: suite × status × tag aggregation,
per-dimension means, pass^k over the epoch dimension (a case passes only if
every epoch passed — partial passes never count), and baseline diff for
regression runs. Output is plain dicts; rendering to JSON/Markdown belongs
to the CLI layer.
"""

from __future__ import annotations

from collections import defaultdict

from .core import Case, RunRecord, Score


def _epoch_of(run_id: str) -> int:
    try:
        return int(run_id.rsplit("#", 1)[1])
    except (IndexError, ValueError):
        return 1


def summarize(
    records: list[RunRecord],
    cases: dict[str, Case],
    scores: dict[str, list[Score]],
    *,
    dimensions: list[str] | None = None,
) -> dict:
    """Aggregate one suite run into the report matrix. Deterministic order:
    cases sorted by id, dimensions sorted by name."""

    by_case: dict[str, list[RunRecord]] = defaultdict(list)
    for record in records:
        by_case[record.case_ref].append(record)

    status_counts = defaultdict(int)
    for record in records:
        status_counts[record.status] += 1

    per_case: list[dict] = []
    dimension_sums: dict[str, list[float]] = defaultdict(list)
    for case_id in sorted(by_case):
        case_runs = by_case[case_id]
        run_entries = []
        case_scores: dict[str, list[float]] = defaultdict(list)
        for record in sorted(case_runs, key=lambda item: item.run_id):
            entry: dict = {
                "run_id": record.run_id,
                "status": record.status,
                "duration_seconds": record.duration_seconds,
                "metrics_raw": record.metrics_raw,
                "error": record.error,
            }
            for score in scores.get(record.run_id, []):
                entry.setdefault("scores", {})[score.scorer] = {
                    "total": score.total,
                    "passed": score.passed,
                    "dimensions": dict(sorted(score.dimensions.items())),
                }
                for name, value in score.dimensions.items():
                    case_scores[name].append(value)
            for name, value in case_scores.items():
                dimension_sums[name].append(sum(value) / len(value))
            run_entries.append(entry)

        # pass^k：每个 epoch（每个 run 视作一次独立采样）都通过才算通过
        passed_flags = [
            all(
                (score.passed is True) or (score.passed is None)
                for score in scores.get(record.run_id, [])
            )
            for record in case_runs
        ]
        per_case.append(
            {
                "case_id": case_id,
                "suite": cases[case_id].suite if case_id in cases else "",
                "tags": sorted(cases[case_id].tags) if case_id in cases else [],
                "runs": run_entries,
                "pass_at_k": {
                    "k": len(case_runs),
                    "all_epochs_passed": all(passed_flags),
                },
            }
        )

    dimension_means = {
        name: round(sum(values) / len(values), 4)
        for name, values in sorted(dimension_sums.items())
    }
    completed = [record for record in records if record.status == "ok"]
    total_tokens = sum(record.metrics_raw.get("total_tokens", 0.0) for record in records)
    return {
        "totals": {
            "cases": len(by_case),
            "runs": len(records),
            "status": dict(sorted(status_counts.items())),
            # 失败/超时不计入通过率分母（设计 §02 口径）
            "pass_rate_over_ok": (
                round(
                    sum(1 for case in per_case if case["pass_at_k"]["all_epochs_passed"])
                    / max(1, len([c for c in per_case if any(r["status"] == "ok" for r in c["runs"])])),
                    4,
                )
            ),
            "total_tokens": int(total_tokens),
            "mean_duration_seconds": (
                round(sum(record.duration_seconds for record in completed) / len(completed), 3)
                if completed
                else 0.0
            ),
        },
        "dimensions": dimension_means,
        "cases": per_case,
    }


def diff_baselines(before: dict, after: dict) -> dict:
    """Regression diff between two summarize() outputs (same suite, two
    versions). Only deltas that matter for gating are surfaced."""

    def _pass_map(report: dict) -> dict[str, bool]:
        return {case["case_id"]: case["pass_at_k"]["all_epochs_passed"] for case in report["cases"]}

    before_pass, after_pass = _pass_map(before), _pass_map(after)
    return {
        "regressions": sorted(case_id for case_id in before_pass if before_pass.get(case_id) and not after_pass.get(case_id)),
        "improvements": sorted(case_id for case_id in before_pass if not before_pass.get(case_id) and after_pass.get(case_id)),
        "dimension_deltas": {
            name: round(after["dimensions"].get(name, 0.0) - before["dimensions"].get(name, 0.0), 4)
            for name in sorted(set(before["dimensions"]) | set(after["dimensions"]))
        },
        "totals_before": before["totals"],
        "totals_after": after["totals"],
    }


def render_markdown(report: dict, *, title: str = "Eval Report") -> str:
    """Minimal deterministic Markdown rendering (CLI layer may re-render)."""

    totals = report["totals"]
    lines = [
        f"# {title}",
        "",
        f"- cases: {totals['cases']} · runs: {totals['runs']} · status: {totals['status']}",
        f"- pass^k rate: {totals['pass_rate_over_ok']} · tokens: {totals['total_tokens']}"
        f" · mean duration: {totals['mean_duration_seconds']}s",
        "",
    ]
    if report["dimensions"]:
        lines.append("| dimension | mean |")
        lines.append("|---|---|")
        for name, value in report["dimensions"].items():
            lines.append(f"| {name} | {value} |")
        lines.append("")
    lines.append("| case | tags | k | all epochs passed |")
    lines.append("|---|---|---|---|")
    for case in report["cases"]:
        tags = ",".join(case["tags"]) or "—"
        lines.append(
            f"| {case['case_id']} | {tags} | {case['pass_at_k']['k']} | "
            f"{'yes' if case['pass_at_k']['all_epochs_passed'] else 'NO'} |"
        )
    return "\n".join(lines) + "\n"
