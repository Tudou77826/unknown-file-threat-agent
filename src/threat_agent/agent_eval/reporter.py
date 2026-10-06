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
        # 维度值按案例累积：案例均值 = 该案例全部 epoch 得分的等权平均
        # （修复：原实现在 epoch 循环内对累积列表求均值，两轮 0/1 会算出 0.25）
        case_dim_values: dict[str, list[float]] = defaultdict(list)
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
                    case_dim_values[name].append(value)
            run_entries.append(entry)
        for name, values in case_dim_values.items():
            dimension_sums[name].append(sum(values) / len(values))

        # pass^k：每个 epoch 都通过才算通过。无评分记录、或所有评分器都
        # 返回 None（不适用）→ 该 run 无法评价：整案标 None，不算通过。
        def _run_outcome(record) -> bool | None:
            if record.status != "ok":
                return False  # error/timeout 的 epoch：没有结果 = 不通过
            run_scores = scores.get(record.run_id, [])
            if not run_scores:
                return None
            judged = [s for s in run_scores if s.passed is not None]
            if not judged:
                return None
            return all(s.passed is True for s in judged)

        passed_flags = [_run_outcome(record) for record in case_runs]
        all_passed: bool | None
        if any(flag is None for flag in passed_flags):
            all_passed = None
        else:
            all_passed = all(flag is True for flag in passed_flags)
        per_case.append(
            {
                "case_id": case_id,
                "suite": cases[case_id].suite if case_id in cases else "",
                "tags": sorted(cases[case_id].tags) if case_id in cases else [],
                "runs": run_entries,
                "pass_at_k": {
                    "k": len(case_runs),
                    "all_epochs_passed": all_passed,
                },
            }
        )

    dimension_means = {
        name: round(sum(values) / len(values), 4)
        for name, values in sorted(dimension_sums.items())
    }
    completed = [record for record in records if record.status == "ok"]
    total_tokens = sum(record.metrics_raw.get("total_tokens", 0.0) for record in records)
    unevaluated = sum(1 for case in per_case if case["pass_at_k"]["all_epochs_passed"] is None)
    rate_denominator = [
        c for c in per_case
        if c["pass_at_k"]["all_epochs_passed"] is not None
        and any(r["status"] == "ok" for r in c["runs"])
    ]
    return {
        "totals": {
            "cases": len(by_case),
            "runs": len(records),
            "status": dict(sorted(status_counts.items())),
            # 失败/超时/无法评价不计入通过率分母（无法评价单列）
            "pass_rate_over_ok": (
                round(
                    sum(1 for case in rate_denominator if case["pass_at_k"]["all_epochs_passed"])
                    / max(1, len(rate_denominator)),
                    4,
                )
            ),
            "unevaluated_cases": unevaluated,
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
        flag = case["pass_at_k"]["all_epochs_passed"]
        mark = "n/a" if flag is None else ("yes" if flag else "NO")
        lines.append(
            f"| {case['case_id']} | {tags} | {case['pass_at_k']['k']} | {mark} |"
        )
    return "\n".join(lines) + "\n"
