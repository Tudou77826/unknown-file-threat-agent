"""Feature 16 kernel gates: contract semantics, runner behavior (idempotent
resume, fresh resampling, failure isolation, concurrency speedup, rate
limiting), two-phase scoring with regrade, and the pass^k reduction.

All tests use fake tasks/scorers — the kernel tests must run offline in
seconds (implementation plan step 01/02 verification thresholds).
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from threat_agent.agent_eval import (
    Case,
    RateLimitConfig,
    RateLimiter,
    RunRecord,
    Runner,
    RunnerConfig,
    Score,
    ScoreRunner,
    Scorer,
    build_run_id,
    config_hash,
    diff_baselines,
    render_markdown,
    summarize,
)


def _case(case_id: str = "case-1", **overrides) -> Case:
    payload = dict(
        case_id=case_id,
        suite="fake-suite@1",
        task_input={"prompt": "do things"},
        environment={"seed": 7},
        ground_truth={"expected_verdict": "likely_malicious"},
        tags=frozenset({"smoke"}),
    )
    payload.update(overrides)
    return Case(**payload)


class _FakeTask:
    """Records workdir usage; sleeps to simulate LLM latency; can fail."""

    def __init__(self, *, sleep: float = 0.0, fail_ids: set[str] | None = None):
        self.sleep = sleep
        self.fail_ids = fail_ids or set()
        self.calls: list[tuple[str, int]] = []
        self._lock = threading.Lock()

    def run_case(self, case: Case, *, epoch: int, workdir: Path) -> dict[str, float]:
        with self._lock:
            self.calls.append((case.case_id, epoch))
        if case.case_id in self.fail_ids:
            raise RuntimeError("synthetic task failure")
        time.sleep(self.sleep)
        (workdir / "transcript.json").write_text(
            json.dumps({"case": case.case_id, "epoch": epoch}), encoding="utf-8"
        )
        return {"iterations": 3.0, "total_tokens": 1500.0}


# ---------------------------------------------------------------------------
# contracts
# ---------------------------------------------------------------------------

def test_run_id_is_the_idempotency_key():
    config = {"model": "m1", "temperature": 0}
    assert build_run_id("case-1", config, 1) == f"case-1#{config_hash(config)}#1"
    # 同 config 同 hash，不同 config 不同 hash
    assert config_hash(config) == config_hash({"temperature": 0, "model": "m1"})
    assert config_hash(config) != config_hash({"model": "m2"})


# ---------------------------------------------------------------------------
# runner behavior
# ---------------------------------------------------------------------------

def test_runner_executes_all_case_epoch_pairs(tmp_path):
    task = _FakeTask()
    results = Runner(
        task, output_dir=tmp_path, config=RunnerConfig(workers=2, epochs=2)
    ).run_suite([_case("a"), _case("b")])

    assert sorted((r.record.case_ref, r.record.run_id.rsplit("#", 1)[1]) for r in results) == [
        ("a", "1"), ("a", "2"), ("b", "1"), ("b", "2")
    ]
    assert all(r.record.status == "ok" for r in results)
    # artifacts landed in the per-run workdir
    first = results[0]
    assert (Path(first.workdir) / "artifacts" / "transcript.json").exists()


def test_runner_resume_skips_finished_and_backfills_failures(tmp_path):
    task = _FakeTask(fail_ids={"b"})
    first = Runner(
        task, output_dir=tmp_path, config=RunnerConfig(workers=2)
    ).run_suite([_case("a"), _case("b")])
    assert {r.record.status for r in first} == {"ok", "error"}
    ok_before = {r.record.run_id for r in first if r.record.status == "ok"}

    # 修复任务后重跑：只有失败的那个真正执行
    fixed = _FakeTask()
    events: list[dict] = []
    second = Runner(
        fixed,
        output_dir=tmp_path,
        config=RunnerConfig(workers=2),
        on_event=events.append,
    ).run_suite([_case("a"), _case("b")])

    assert [e["type"] for e in events if e["type"] == "skip"] and [
        e["run_id"] for e in events if e["type"] == "skip"
    ] == sorted(ok_before)
    assert [c for c, _e in fixed.calls] == ["b"]
    assert len(second) == 2 and all(r.record.status == "ok" for r in second)


def test_runner_fresh_resamples_everything(tmp_path):
    Runner(task := _FakeTask(), output_dir=tmp_path, config=RunnerConfig()).run_suite([_case()])
    before = len(task.calls)

    second_task = _FakeTask()
    Runner(
        second_task, output_dir=tmp_path, config=RunnerConfig(fresh=True)
    ).run_suite([_case()])
    assert len(second_task.calls) == before  # fresh 时不跳过任何 run


def test_single_case_failure_does_not_break_the_batch(tmp_path):
    task = _FakeTask(fail_ids={"bad", "worse"})
    results = Runner(
        task, output_dir=tmp_path, config=RunnerConfig(workers=3)
    ).run_suite([_case("bad"), _case("good"), _case("worse")])

    by_case = {r.record.case_ref: r.record for r in results}
    assert by_case["bad"].status == "error" and "synthetic" in (by_case["bad"].error or "")
    assert by_case["good"].status == "ok"
    assert by_case["worse"].status == "error"


def test_concurrency_speedup_near_linear(tmp_path):
    sleep = 0.6
    cases = [_case(f"c{i}") for i in range(6)]

    serial_start = time.monotonic()
    Runner(
        _FakeTask(sleep=sleep), output_dir=tmp_path / "serial", config=RunnerConfig(workers=1)
    ).run_suite(cases)
    serial = time.monotonic() - serial_start

    parallel_start = time.monotonic()
    Runner(
        _FakeTask(sleep=sleep), output_dir=tmp_path / "par", config=RunnerConfig(workers=6)
    ).run_suite(cases)
    parallel = time.monotonic() - parallel_start

    # 门槛：加速比 ≥ 线程数 × 0.8（计划 01 验收）
    assert serial / parallel >= 6 * 0.8, f"serial={serial:.2f}s parallel={parallel:.2f}s"


def test_rate_limiter_blocks_over_cap_and_counts_429_backoff():
    # 桶容量 = 整分钟预算（rpm=600，突发额度 600，回填 10/s）：
    # 突发额度内即时；耗尽后必须等回填。
    limiter = RateLimiter(RateLimitConfig(rpm=600))
    start = time.monotonic()
    for _ in range(605):
        limiter.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.3, f"605 acquisitions at 10/s refill should take ≥0.3s, took {elapsed:.3f}s"

    limiter.register_429()
    assert limiter.throttled_acquires == 1
    limiter.register_success()
    # 成功后冷却清零：下一次 acquire 至多等一个短回填窗口，不再受 429 冷却拖累
    start = time.monotonic()
    limiter.acquire()
    assert time.monotonic() - start < 1.0


# ---------------------------------------------------------------------------
# scoring: two-phase, regrade, dimension scores
# ---------------------------------------------------------------------------

class _VerdictScorer(Scorer):
    name = "verdict_match"

    def score(self, record: RunRecord, case: Case) -> Score:
        if record.status != "ok":
            return Score(scorer=self.name, total=0.0, passed=False,
                         notes=["run 未完成，不适用打分"])
        path = Path(record.artifacts.get("report") or "")
        predicted = json.loads(path.read_text(encoding="utf-8"))["verdict"] if path.exists() else None
        expected = case.ground_truth["expected_verdict"]
        return Score(
            scorer=self.name,
            dimensions={"verdict_correct": 1.0 if predicted == expected else 0.0},
            total=1.0 if predicted == expected else 0.0,
            passed=predicted == expected,
            notes=[f"expected={expected} predicted={predicted}"],
        )


def _run_with_artifact(tmp_path: Path, case_id: str, verdict: str, status: str = "ok") -> RunRecord:
    artifact = tmp_path / f"{case_id}-{verdict}.json"
    artifact.write_text(json.dumps({"verdict": verdict}), encoding="utf-8")
    return RunRecord(
        run_id=build_run_id(case_id, {}, 1),
        case_ref=case_id,
        status=status,  # type: ignore[arg-type]
        metrics_raw={"iterations": 4, "total_tokens": 900},
        artifacts={"report": str(artifact)},
        duration_seconds=1.2,
    )


def test_scorer_reads_raw_artifacts_and_reports_dimensions(tmp_path):
    runner = ScoreRunner([_VerdictScorer()])
    case = _case("a")
    hit = runner.score_record(_run_with_artifact(tmp_path, "a", "likely_malicious"), case)
    miss = runner.score_record(_run_with_artifact(tmp_path, "a", "benign"), case)

    assert hit[0].passed is True and hit[0].dimensions["verdict_correct"] == 1.0
    assert "expected=" in hit[0].notes[0]
    assert miss[0].passed is False and miss[0].total == 0.0


def test_failed_run_scores_as_not_passed_with_note(tmp_path):
    record = _run_with_artifact(tmp_path, "x", "whatever", status="error")
    record.artifacts = {}
    scores = ScoreRunner([_VerdictScorer()]).score_record(record, _case("x"))
    assert scores[0].passed is False and "未完成" in scores[0].notes[0]


def test_scorer_exception_is_recorded_not_raised(tmp_path):
    class _Broken:
        name = "broken"

        def score(self, record, case):
            raise ValueError("boom")

    scores = ScoreRunner([_Broken()]).score_record(_run_with_artifact(tmp_path, "a", "x"), _case("a"))
    assert scores[0].passed is False and "boom" in scores[0].notes[0]


# ---------------------------------------------------------------------------
# reporter: aggregation, pass^k, regression diff, markdown
# ---------------------------------------------------------------------------

def _scored(runner_records, scorer_results):
    return {
        record.run_id: [
            Score(scorer="verdict_match", total=total, passed=passed, dimensions={"v": total})
        ]
        for record, (total, passed) in zip(runner_records, scorer_results)
    }


def test_summarize_pass_at_k_partial_never_counts():
    cases = {"a": _case("a"), "b": _case("b")}
    ra1 = _run_with_artifact(Path("."), "a", "v1")
    ra2 = _run_with_artifact(Path("."), "a", "v2")
    rb1 = _run_with_artifact(Path("."), "b", "v3")
    rb2 = _run_with_artifact(Path("."), "b", "v4")
    ra1.run_id, ra2.run_id = build_run_id("a", {}, 1), build_run_id("a", {}, 2)
    rb1.run_id, rb2.run_id = build_run_id("b", {}, 1), build_run_id("b", {}, 2)

    records = [ra1, ra2, rb1, rb2]
    scores = _scored(records, [(1.0, True), (0.0, False), (1.0, True), (1.0, True)])

    report = summarize(records, cases, scores)
    by_case = {c["case_id"]: c for c in report["cases"]}
    # case a: 3 过 1 不过 → pass^k 不通过
    assert by_case["a"]["pass_at_k"] == {"k": 2, "all_epochs_passed": False}
    assert by_case["b"]["pass_at_k"]["all_epochs_passed"] is True


def test_summarize_excludes_failures_from_pass_rate_denominator():
    cases = {"a": _case("a")}
    ok_run = _run_with_artifact(Path("."), "a", "v")
    ok_run.run_id = build_run_id("a", {}, 1)
    bad_run = _run_with_artifact(Path("."), "a", "v", status="error")
    bad_run.run_id = build_run_id("a", {}, 2)
    scores = _scored([ok_run], [(1.0, True)])

    report = summarize([ok_run, bad_run], cases, {**scores, bad_run.run_id: []})
    assert report["totals"]["status"] == {"error": 1, "ok": 1}
    assert report["totals"]["pass_rate_over_ok"] == 1.0


def test_diff_baselines_flags_regression_and_improvement():
    def _report(passed: dict[str, bool], dim: float) -> dict:
        return {
            "totals": {"cases": len(passed), "runs": len(passed), "status": {"ok": len(passed)},
                       "pass_rate_over_ok": sum(passed.values()) / len(passed),
                       "total_tokens": 0, "mean_duration_seconds": 0.0},
            "dimensions": {"verdict": dim},
            "cases": [
                {"case_id": case_id, "suite": "s", "tags": [],
                 "runs": [], "pass_at_k": {"k": 1, "all_epochs_passed": passed}}
                for case_id, passed in passed.items()
            ],
        }

    diff = diff_baselines(_report({"a": True, "b": False}, 0.5), _report({"a": True, "b": True}, 0.8))
    assert diff["regressions"] == []
    assert diff["improvements"] == ["b"]
    assert diff["dimension_deltas"]["verdict"] == 0.3

    diff2 = diff_baselines(_report({"a": True}, 0.9), _report({"a": False}, 0.1))
    assert diff2["regressions"] == ["a"]


def test_render_markdown_is_deterministic():
    report = {
        "totals": {"cases": 1, "runs": 1, "status": {"ok": 1}, "pass_rate_over_ok": 1.0,
                   "total_tokens": 900, "mean_duration_seconds": 1.2},
        "dimensions": {"verdict": 1.0},
        "cases": [{"case_id": "a", "suite": "s@1", "tags": ["smoke"], "runs": [],
                   "pass_at_k": {"k": 1, "all_epochs_passed": True}}],
    }
    assert render_markdown(report) == render_markdown(report)
    assert "pass^k rate: 1.0" in render_markdown(report)
    assert "| a | smoke | 1 | yes |" in render_markdown(report)
