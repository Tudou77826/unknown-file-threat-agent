"""F16 步骤 03 — 评测 CLI：跑批 → 回填产物清单 → 离线打分 → 报表。

用法：
    python -m threat_agent.bootstrap.eval_cli --name baseline        # 全套件
    python -m threat_agent.bootstrap.eval_cli --smoke                # 单案例冒烟
    python -m threat_agent.bootstrap.eval_cli --score-only --name baseline  # 只重打分
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..agent_eval.core import Case, RunRecord
from ..agent_eval.rate_limit import RateLimitConfig, RateLimiter
from ..agent_eval.reporter import render_markdown, summarize
from ..agent_eval.runner import Runner, RunnerConfig
from ..agent_eval.scoring import ScoreRunner
from ..bootstrap.eval_scorers import default_scorers
from ..bootstrap.eval_tasks import (
    SUITE,
    SecAgentEvalTask,
    build_eval_cases,
    build_validation_cases,
)
from ..bootstrap.settings import AppSettings

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _fill_artifacts(results) -> None:
    """把 artifacts 目录清单回填进 RunRecord（内核只负责执行与落盘）。"""

    for result in results:
        artifacts_dir = Path(result.workdir) / "artifacts"
        if artifacts_dir.exists():
            result.record.artifacts = {
                path.stem: path.name
                for path in sorted(artifacts_dir.iterdir())
                if path.is_file()
            }
        (Path(result.workdir) / "run_record.json").write_text(
            result.record.model_dump_json(), encoding="utf-8"
        )


def _load_cases(output_dir: Path, fresh_cases: list[Case]) -> dict[str, Case]:
    """score-only 依赖运行时落盘的 cases.json（含 ground_truth）。"""

    path = output_dir / "cases.json"
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
        return {item["case_id"]: Case.model_validate(item) for item in payload}
    return {case.case_id: case for case in fresh_cases}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="baseline", help="输出目录名（outputs/eval/<name>）")
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=900.0)
    parser.add_argument("--rpm", type=int, default=60, help="0=不限")
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--smoke", action="store_true", help="只跑 1 个代表案例（L3 恶意）")
    parser.add_argument("--suite", choices=["demo", "validation"], default="demo",
                        help="demo=数据完整度轴（L0-L3）；validation=F19 技术覆盖轴（ATT&CK 剧本）")
    parser.add_argument("--score-only", action="store_true", help="跳过执行，仅对已有 run 重打分")
    args = parser.parse_args(argv)

    output_dir = PROJECT_ROOT / "outputs" / "eval" / args.name
    settings = AppSettings.load(cli_overrides={})
    validation_roots = None
    if args.suite == "validation":
        validation_roots = [PROJECT_ROOT / "validation_cases", PROJECT_ROOT / "validation_cases_staging"]
        cases = build_validation_cases(validation_roots)
    else:
        cases = build_eval_cases(PROJECT_ROOT / "demo_data")
    if args.smoke:
        cases = [
            case
            for case in cases
            if case.case_id.endswith("-l3") and "adversarial" not in case.tags
        ][:1] or cases[:1]  # validation 套件无 -l3 后缀，退回首个案例

    if not args.score_only:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "cases.json").write_text(
            json.dumps([case.model_dump(mode="json") for case in cases], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        task = SecAgentEvalTask(
            settings=settings,
            project_root=PROJECT_ROOT,
            reference_dir=output_dir / "reference",
            validation_roots=validation_roots,
        )
        # 并发 worker 是多进程：线程锁挡不住并发导入。派发前同步建好参考库，
        # 避免首案撞上"导入进行中"的半成品（Unknown data profile 竞态实证）。
        task._reference_store()
        limiter = RateLimiter(RateLimitConfig(rpm=args.rpm, tpm=0)) if args.rpm else None

        def _on_event(event: dict) -> None:
            print(
                f"[{event.get('type')}] {event.get('run_id', '')} "
                f"{event.get('status', '') or str(event.get('error', ''))[:120]}",
                flush=True,
            )
            # run_record 只留错误首行；完整 traceback 落盘到固定文件，
            # 否则崩溃类错误（如此前的 datetime 序列化）只能靠复现定位。
            if event.get("type") == "case_error":
                with (output_dir / "case_errors.jsonl").open("a", encoding="utf-8") as sink:
                    sink.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")

        runner = Runner(
            task,
            output_dir=output_dir,
            config=RunnerConfig(
                workers=args.workers,
                epochs=args.epochs,
                fresh=args.fresh,
                timeout_seconds=args.timeout,
            ),
            limiter=limiter,
            on_event=_on_event,
        )
        results = runner.run_suite(cases)
        _fill_artifacts(results)
        records = [result.record for result in results]
    else:
        records = []
        runs_dir = output_dir / "runs"
        if runs_dir.exists():
            for record_path in sorted(runs_dir.glob("*/run_record.json")):
                records.append(
                    RunRecord.model_validate_json(record_path.read_text(encoding="utf-8"))
                )

    case_by_id = _load_cases(output_dir, cases)
    score_runner = ScoreRunner(default_scorers(output_dir))
    pairs = [
        (record, case_by_id[record.case_ref])
        for record in records
        if record.case_ref in case_by_id
    ]
    scores = score_runner.score_all(
        pairs,
        workdir_of=lambda run_id: output_dir / "runs" / run_id.replace("#", "_") / "artifacts",
    )
    report = summarize(records, case_by_id, scores)
    # 报告版本化：预期判定的任何调整必须更换 --name 出新报告并在 meta 注明原因；
    # 旧报告原样保留，不追溯重算（工程师复核裁决）。
    report["meta"] = {
        "generated_at": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
        "suite": args.suite,
        "model": settings.judgment_model.model_name,
        "expectations_note": "预期判定版本随套件文件；如调整见 .sdd 对应记录",
    }
    (output_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
    (output_dir / "report.md").write_text(
        render_markdown(report, title=f"SecAgent Eval — {args.name}"), encoding="utf-8"
    )
    print(f"report: {output_dir / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
