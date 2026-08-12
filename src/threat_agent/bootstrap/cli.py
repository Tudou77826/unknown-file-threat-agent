from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..case_management import CaseGraph, build_case_read_model, create_memory_checkpointer, create_sqlite_checkpointer, initialize_state
from ..contracts import CaseReadModel
from ..data_foundation import FixtureEvidenceRepository, JsonlEventRepository
from ..judgment import DeterministicPlanner, JudgmentGraph, StructuredJudgmentPlanner, ToolRegistry
from ..judgment.domain.models import InvestigationState
from ..presentation import case_read_payload
from ..case_management.application.reporting import write_reports
from ..response_advisory import DeterministicResponsePlanner, ResponseGraph, StructuredResponsePlanner
from .settings import AppSettings, build_judgment_model, build_response_model

PROJECT_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class PlatformRun:
    state: InvestigationState
    read_model: CaseReadModel
    graph_state: dict[str, Any]


def _interrupt_value(result: dict[str, Any]) -> dict[str, Any] | None:
    interrupts = result.get("__interrupt__") or []
    if not interrupts:
        return None
    value = getattr(interrupts[0], "value", None)
    return value if isinstance(value, dict) else None


def run_platform_case(
    case_dir: Path,
    mode: str = "deterministic",
    output_dir: Path | None = None,
    *,
    tenant_id: str = "default",
    run_id: str = "primary",
    checkpoint_path: Path | None = None,
    approve_scope: bool = False,
    approve_response: bool = False,
    settings: AppSettings | None = None,
) -> PlatformRun:
    settings = settings or AppSettings.load()
    raw = json.loads((case_dir / "input.json").read_text(encoding="utf-8"))
    raw.setdefault("tenant_id", tenant_id)
    state = initialize_state(raw)
    state.budget.max_iterations = settings.judgment_budget.max_iterations
    state.budget.max_tool_calls = settings.judgment_budget.max_tool_calls
    state.budget.max_scope_expansions = settings.judgment_budget.max_scope_expansions
    state.budget.max_repair_actions = settings.judgment_budget.max_repair_actions
    state.budget.max_verdict_repairs = settings.judgment_budget.max_verdict_repairs
    repository = (
        JsonlEventRepository(case_dir)
        if (case_dir / "events").is_dir()
        else FixtureEvidenceRepository(case_dir)
    )
    registry = ToolRegistry(
        repository,
        query_default_limit=settings.evidence_query.default_limit,
        query_max_limit=settings.evidence_query.max_limit,
    )
    if mode in {"llm", "deepagents"}:
        settings.require_models()
        judgment_planner = StructuredJudgmentPlanner(build_judgment_model(settings), registry)
        response_planner = StructuredResponsePlanner(build_response_model(settings))
    else:
        judgment_planner = DeterministicPlanner()
        response_planner = DeterministicResponsePlanner()
    judgment_graph = JudgmentGraph(
        registry,
        judgment_planner,
        scope_approval_mode="defer",
        recursion_limit=settings.graph.recursion_limit,
    )
    response_graph = ResponseGraph(
        response_planner,
        max_iterations=settings.response_budget.max_iterations,
        recursion_limit=settings.graph.recursion_limit,
    )
    effective_checkpoint_path = checkpoint_path
    if effective_checkpoint_path is None and settings.checkpoint.backend == "sqlite":
        effective_checkpoint_path = settings.checkpoint.path
    checkpointer = (
        create_sqlite_checkpointer(effective_checkpoint_path)
        if effective_checkpoint_path is not None
        else create_memory_checkpointer()
    )
    graph = CaseGraph(
        judgment_graph,
        checkpointer=checkpointer,
        response_graph=response_graph,
        recursion_limit=settings.graph.recursion_limit,
    )
    result = graph.start(state, tenant_id=tenant_id, run_id=run_id)
    while (request := _interrupt_value(result)) is not None:
        if request.get("kind") == "scope_approval":
            result = graph.resume_scope(
                tenant_id=tenant_id,
                case_id=state.case_id,
                run_id=run_id,
                approved=approve_scope,
                approved_by="cli-policy",
            )
        elif request.get("kind") == "response_approval":
            result = graph.resume_response(
                tenant_id=tenant_id,
                case_id=state.case_id,
                run_id=run_id,
                approved=approve_response,
                approved_by="cli-policy",
            )
        else:
            raise RuntimeError(f"Unsupported graph interrupt: {request!r}")
    completed = InvestigationState.model_validate(result["investigation"])
    read_model = build_case_read_model(
        completed,
        tenant_id=tenant_id,
        lifecycle_status=str(result["lifecycle_status"]),
        judgment=result.get("judgment_result"),
        response_plan=result.get("response_plan"),
        approval_status=result.get("approval_status"),
    )
    if output_dir:
        expected_path = case_dir / "expected.json"
        expected = (
            json.loads(expected_path.read_text(encoding="utf-8"))
            if expected_path.exists()
            else None
        )
        write_reports(completed, output_dir, expected, read_model=read_model)
    platform_run = PlatformRun(state=completed, read_model=read_model, graph_state=result)
    if effective_checkpoint_path is not None:
        checkpointer.conn.close()
    return platform_run


def run_case(case_dir: Path, mode: str = "deterministic", output_dir: Path | None = None):
    """Compatibility entry returning InvestigationState through the platform graph."""

    return run_platform_case(case_dir, mode, output_dir).state


def main() -> None:
    parser = argparse.ArgumentParser(description="Unknown-file security analysis platform")
    parser.add_argument(
        "--case",
        default=None,
        help="Case directory containing input.json and event data",
    )
    parser.add_argument(
        "--mode",
        choices=["deterministic", "llm", "deepagents"],
        default=None,
        help="Use 'llm' for both planning loops; 'deepagents' is a compatibility alias",
    )
    parser.add_argument("--tenant", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--checkpoint", help="SQLite checkpoint database path")
    parser.add_argument("--approve-scope", action="store_true")
    parser.add_argument("--approve-response", action="store_true")
    parser.add_argument("--output", help="Directory for report.json, report.md and evaluation.json")
    args = parser.parse_args()
    overrides = {
        "THREAT_AGENT_DEFAULT_CASE_DIR": args.case,
        "THREAT_AGENT_MODE": args.mode,
        "THREAT_AGENT_DEFAULT_TENANT": args.tenant,
        "THREAT_AGENT_DEFAULT_RUN_ID": args.run_id,
        "THREAT_AGENT_OUTPUT_DIR": args.output,
        "THREAT_AGENT_CHECKPOINT_BACKEND": "sqlite" if args.checkpoint else None,
        "THREAT_AGENT_CHECKPOINT_PATH": args.checkpoint,
    }
    settings = AppSettings.load(cli_overrides=overrides)
    result = run_platform_case(
        settings.application.default_case_dir,
        settings.application.mode,
        settings.application.output_dir,
        tenant_id=settings.application.default_tenant,
        run_id=settings.application.default_run_id,
        checkpoint_path=settings.checkpoint.path if settings.checkpoint.backend == "sqlite" else None,
        approve_scope=args.approve_scope,
        approve_response=args.approve_response,
        settings=settings,
    )
    print(json.dumps(case_read_payload(result.read_model), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
