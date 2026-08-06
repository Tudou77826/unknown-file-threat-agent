from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import InvestigationEngine
from .ingestion import initialize_state
from .planner import DeepAgentsPlanner, DeterministicPlanner
from .reporting import report_payload, write_reports
from .repository import FixtureEvidenceRepository, JsonlEventRepository
from .tools import ToolRegistry

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASE_DIR = PROJECT_ROOT / "cases" / "c2_malicious"


def run_case(case_dir: Path, mode: str = "deterministic", output_dir: Path | None = None):
    raw = json.loads((case_dir / "input.json").read_text(encoding="utf-8"))
    state = initialize_state(raw)
    repository = JsonlEventRepository(case_dir) if (case_dir / "events").is_dir() else FixtureEvidenceRepository(case_dir)
    registry = ToolRegistry(repository)
    if mode == "deepagents":
        from .model_config import build_chat_model

        planner = DeepAgentsPlanner(build_chat_model(), registry)
    else:
        planner = DeterministicPlanner()
    state = InvestigationEngine(registry, planner).run(state)
    if output_dir:
        expected_path = case_dir / "expected.json"
        expected = json.loads(expected_path.read_text(encoding="utf-8")) if expected_path.exists() else None
        write_reports(state, output_dir, expected)
    return state


def main() -> None:
    parser = argparse.ArgumentParser(description="Linux unknown-file threat investigation agent V1")
    parser.add_argument(
        "--case",
        default=str(DEFAULT_CASE_DIR),
        help=f"Case directory containing input.json and evidence.json (default: {DEFAULT_CASE_DIR})",
    )
    parser.add_argument("--mode", choices=["deterministic", "deepagents"], default="deepagents")
    parser.add_argument("--output", help="Directory for report.json and report.md")
    args = parser.parse_args()
    state = run_case(Path(args.case), args.mode, Path(args.output) if args.output else None)
    print(json.dumps(report_payload(state), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
