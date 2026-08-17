from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Callable

from ..case_management import (
    CaseGraph,
    SingleHostBoundaryPolicy,
    build_case_read_model,
    create_memory_checkpointer,
    initialize_state,
)
from ..case_management.application import evaluate_data_readiness
from ..contracts import CaseReadModel, DemoComparisonReadModel, ProfileComparisonItem
from ..data_foundation.adapters import (
    SQLiteActivityQueryAdapter, SQLiteActivityStore,
    SQLiteReferenceDataStore,
)
from ..data_foundation.application import initialize_reference_demo, reference_activity_store_path
from ..judgment import (
    InvestigationToolGateway,
    JudgmentGraph,
    ReportGroundingValidator,
    ReportPublisher,
    ReportRepairCoordinator,
    StructuredDataToolPlanner,
    StructuredReportComposer,
)
from ..judgment.application.tool_observation import ToolObservationSummarizer
from ..presentation import InMemoryCaseReadStore, InMemoryDemoComparisonStore
from ..presentation.api.routes import create_app
from ..response_advisory import ResponseGraph, StructuredResponsePlanner
from ..response_advisory.adapters import ReferenceResponseContextAdapter
from .settings import (
    AppSettings,
    PROJECT_ROOT,
    build_judgment_model,
    build_report_model,
    build_response_model,
    format_effective_settings,
)


EventSink = Callable[[str, str, dict[str, Any] | None], None]

VERDICT_LABEL_ZH = {
    "confirmed_malicious": "确认恶意",
    "likely_malicious": "高度疑似恶意",
    "suspicious": "存在可疑行为",
    "insufficient_evidence": "证据不足",
    "likely_benign": "倾向良性",
    "benign": "确认良性",
}

VERDICT_SUMMARY_ZH = {
    "confirmed_malicious": "现有证据已满足恶意行为确认门槛，并形成可追溯的攻击活动链。",
    "likely_malicious": "多项行为支持恶意假设，但仍缺少完成确认或排除反证所需的数据。",
    "suspicious": "已观察到需要继续调查的可疑行为，当前证据不足以完成定性。",
    "insufficient_evidence": "当前数据无法回答关键调查问题，系统保持证据不足结论。",
    "likely_benign": "现有证据更支持合法活动解释，但结论仍受数据覆盖限制。",
    "benign": "软件来源与批准业务行为构成完整反证，支持良性结论。",
}


def localize_verdict(judgment) -> None:
    level = judgment.verdict.level.value
    judgment.verdict.summary = VERDICT_SUMMARY_ZH.get(level, judgment.verdict.summary)


class ObservableJudgmentPlanner:
    def __init__(self, delegate, emit: EventSink, observation_summarizer=None):
        self.delegate = delegate
        self.emit = emit
        self.uses_data_tools = bool(getattr(delegate, "uses_data_tools", False))
        self.observation_summarizer = observation_summarizer
        self._summarized_trace_count = 0

    def plan(self, state):
        self._summarize_previous_round(state)
        self.emit("thinking", "研判模型正在选择下一步调查动作", {
            "node": "plan",
            "iteration": state.budget.iterations_used,
        })
        started = time.perf_counter()
        actions = list(self.delegate.plan(state))
        duration_ms = round((time.perf_counter() - started) * 1000, 3)
        for action in actions:
            self.emit("decision", f"研判模型选择：{action.action_type}", {
                "node": "plan",
                "tool_name": getattr(action, "tool_name", None),
                "objective": action.objective,
                "duration_ms": duration_ms,
            })
        return actions

    def _summarize_previous_round(self, state) -> None:
        """Emit one round-level observation for the tools executed last round.

        The unit of observation is the round, not the individual tool, so this
        performs a single LLM call aggregating the round's results.
        """
        if self.observation_summarizer is None:
            return
        traces = state.tool_ledger.traces
        new_traces = traces[self._summarized_trace_count:]
        if not new_traces:
            return
        round_num = max(1, state.budget.iterations_used - 1)
        items = [(trace.tool_name, trace.result) for trace in new_traces]
        try:
            summary = self.observation_summarizer.summarize_round(items)
        except Exception:
            summary = None
        self._summarized_trace_count = len(traces)
        self.emit("round", f"第 {round_num} 轮调查完成", {
            "node": "execute",
            "round": round_num,
            "tool_names": [trace.tool_name for trace in new_traces],
            "observation": summary,
        })


class ObservableReportComposer:
    """Emit workflow events around draft composition and rejudgment."""

    def __init__(self, delegate, emit: EventSink):
        self.delegate = delegate
        self.emit = emit
        self.model_name = getattr(delegate, "model_name", "unknown")

    def compose_draft(self, state):
        self.emit("thinking", "研判模型正在综合证据并形成报告草稿", {
            "node": "compose",
            "query_count": len(state.tool_ledger.query_results),
            "activity_count": len(state.tool_ledger.authorized_activity_refs),
        })
        return self.delegate.compose_draft(state)

    def rejudge(self, state, previous_draft, issues, *, attempt):
        self.emit("thinking", f"研判模型正在按授权证据白名单重新研判（第 {attempt} 次）", {
            "node": "gate",
            "attempt": attempt,
            "issue_codes": sorted({issue.code for issue in issues}),
        })
        return self.delegate.rejudge(state, previous_draft, issues, attempt=attempt)


class ObservableReportPublisher:
    """Emit publication events; reports become visible to observers only here."""

    def __init__(self, delegate, emit: EventSink):
        self.delegate = delegate
        self.emit = emit
        self._verdict_emitted = False

    def publish(self, state, draft, *, publication_status):
        report = self.delegate.publish(state, draft, publication_status=publication_status)
        level = report.verdict.level.value
        self.emit("report", "正式调查报告已发布" if publication_status == "grounded" else "已发布证据不足兜底报告", {
            "node": "compose",
            "report_id": report.report_id,
            "publication_status": publication_status,
            "verdict": level,
            "rejudgments_used": state.budget.report_rejudgments_used,
        })
        if not self._verdict_emitted:
            self._verdict_emitted = True
            self.emit("verdict", f"研判结论：{VERDICT_LABEL_ZH.get(level, level)}", {
                "node": "gate",
                "verdict": level,
                "publication_status": publication_status,
                "summary": VERDICT_SUMMARY_ZH.get(level, report.verdict.summary),
                "supporting_refs": report.verdict.supporting_refs,
                "contradicting_refs": report.verdict.contradicting_refs,
            })
        return report


class ObservableResponsePlanner:
    def __init__(self, delegate, emit: EventSink):
        self.delegate = delegate
        self.emit = emit
        self._response_emitted = False

    def propose(self, judgment, knowledge, validation_errors, response_context=None):
        self.emit("thinking", "处置模型正在结合研判结果与资产上下文生成建议", {
            "node": "advise",
            "verdict": judgment.verdict.level.value,
            "validation_errors": validation_errors,
        })
        started = time.perf_counter()
        proposal = self.delegate.propose(
            judgment, knowledge, validation_errors, response_context
        )
        duration_ms = round((time.perf_counter() - started) * 1000, 3)
        if not self._response_emitted:
            self._response_emitted = True
            self.emit("response", f"处置模型生成 {len(proposal.actions)} 项建议", {
                "node": "advise",
                "action_types": [item.action_type for item in proposal.actions],
                "duration_ms": duration_ms,
            })
        return proposal


def _interrupt_value(result: dict[str, Any]) -> dict[str, Any] | None:
    interrupts = result.get("__interrupt__") or []
    if not interrupts:
        return None
    value = getattr(interrupts[0], "value", None)
    return value if isinstance(value, dict) else None


def run_demo_profile(
    store: SQLiteReferenceDataStore,
    *,
    dataset_id: str,
    dataset_version: str | None = None,
    case_id: str | None = None,
    profile_id: str,
    settings: AppSettings,
    emit: EventSink | None = None,
    run_id: str | None = None,
) -> ProfileComparisonItem:
    emit = emit or (lambda _kind, _message, _details=None: None)
    dataset_version = dataset_version or settings.demo.dataset_version
    if case_id is None:
        row = store.connection.execute(
            "SELECT case_id FROM cases WHERE dataset_id=? AND dataset_version=?",
            (dataset_id, dataset_version),
        ).fetchone()
        if row is None:
            raise KeyError(f"Reference dataset has no case: {dataset_id}/{dataset_version}")
        case_id = str(row["case_id"])
    profile = store.get_profile(dataset_id, dataset_version, profile_id)
    raw = store.get_case_input(dataset_id, dataset_version, case_id)
    state = initialize_state(
        raw, lookback_hours=settings.application.investigation_lookback_hours
    )
    state.budget.max_iterations = settings.judgment_budget.max_iterations
    state.budget.max_tool_calls = settings.judgment_budget.max_tool_calls
    state.budget.max_report_rejudgments = settings.judgment_budget.max_report_rejudgments
    effective_run_id = run_id or f"demo-{dataset_id}-{profile.level}"
    state.raw_input["run_id"] = effective_run_id

    settings.require_models()
    activity_store = SQLiteActivityStore(reference_activity_store_path(store.path, dataset_id))
    activity_query_adapter = SQLiteActivityQueryAdapter(
        activity_store, visible_sources=set(profile.visible_sources)
    )
    # Server-side run identity and the single-host boundary policy are injected
    # here; alert-payload fields can never override the tenant. The tenant is
    # the ONE configured server tenant — it must match the tenant the
    # reference activity data was ingested under, or every query returns zero
    # rows.
    tenant_id = settings.application.default_tenant
    boundary_policy = SingleHostBoundaryPolicy(
        tenant_id=tenant_id,
        case_id=state.case_id,
        run_id=effective_run_id,
    )
    judgment_planner = ObservableJudgmentPlanner(
        StructuredDataToolPlanner(
            build_judgment_model(settings),
            emit,
            context_window_tokens=settings.judgment_model.context_window_tokens,
            output_reserve_tokens=settings.judgment_model.max_tokens,
        ),
        emit,
        observation_summarizer=ToolObservationSummarizer(build_judgment_model(settings)),
    )
    report_composer = ObservableReportComposer(
        StructuredReportComposer(
            build_report_model(settings), emit, tenant_id=tenant_id
        ),
        emit,
    )
    response_planner = ObservableResponsePlanner(
        StructuredResponsePlanner(build_response_model(settings), emit), emit
    )
    judgment_graph = JudgmentGraph(
        judgment_planner,
        tenant_id=tenant_id,
        run_id=effective_run_id,
        data_tool_gateway=InvestigationToolGateway(
            activity_store,
            activity_query_adapter,
            boundary_policy,
            event_sink=emit,
        ),
        report_composer=report_composer,
        report_coordinator=ReportRepairCoordinator(
            report_composer, ReportGroundingValidator(), event_sink=emit,
        ),
        report_publisher=ObservableReportPublisher(
            ReportPublisher(
                tenant_id=tenant_id,
                run_id=effective_run_id,
                model_name=report_composer.model_name,
            ),
            emit,
        ),
        recursion_limit=settings.graph.recursion_limit,
    )
    response_graph = ResponseGraph(
        response_planner,
        response_context_port=ReferenceResponseContextAdapter(
            store,
            dataset_id=dataset_id,
            dataset_version=dataset_version,
            profile=profile,
        ),
        max_iterations=settings.response_budget.max_iterations,
        recursion_limit=settings.graph.recursion_limit,
    )
    graph = CaseGraph(
        judgment_graph,
        checkpointer=create_memory_checkpointer(),
        response_graph=response_graph,
        recursion_limit=settings.graph.recursion_limit,
    )
    emit("graph", "LangGraph 调查流程已启动", {
        "node": "intake",
        "profile": profile.profile_id,
        "planner_mode": "llm",
    })
    result = graph.start(state, tenant_id=tenant_id, run_id=effective_run_id)
    while (request := _interrupt_value(result)) is not None:
        if request.get("kind") == "response_approval":
            emit("approval", "演示策略不批准执行高影响处置", {
                "node": "approve",
                "approval_kind": "response", "approved": False,
                "request_ref": request.get("case_id"),
            })
            result = graph.resume_response(
                tenant_id=tenant_id, case_id=state.case_id, run_id=effective_run_id,
                approved=False, approved_by="reference-demo-policy",
            )
        else:
            raise RuntimeError(f"Unsupported graph interrupt: {request!r}")
    activity_store.close()
    completed = type(state).model_validate(result["investigation"])
    read_model = build_case_read_model(
        completed,
        tenant_id=tenant_id,
        lifecycle_status=str(result["lifecycle_status"]),
        judgment=result.get("judgment_result"),
        response_plan=result.get("response_plan"),
        approval_status=result.get("approval_status"),
    )
    if read_model.judgment is not None:
        localize_verdict(read_model.judgment)
    readiness = evaluate_data_readiness(
        profile, case_id=case_id, tenant_id=tenant_id, run_id=effective_run_id
    )
    level = read_model.judgment.verdict.level.value
    emit("result", f"案件处理完成：{VERDICT_LABEL_ZH.get(level, level)}", {
        "node": "done",
        "summary": read_model.judgment.verdict.summary,
        "answerable_questions": len(readiness.answerable_questions),
    })
    return ProfileComparisonItem(
        profile_id=profile.profile_id,
        level=profile.level,
        readiness=readiness,
        case=read_model,
        investigation_report=result.get("investigation_report"),
    )


def run_demo_comparison(
    *,
    store: SQLiteReferenceDataStore,
    dataset_id: str,
    settings: AppSettings,
) -> DemoComparisonReadModel:
    metadata = store.get_dataset(dataset_id, settings.demo.dataset_version)
    if metadata.random_seed != settings.demo.random_seed:
        raise RuntimeError(
            f"Reference dataset seed mismatch: expected {settings.demo.random_seed}, "
            f"got {metadata.random_seed}"
        )
    row = store.connection.execute(
        "SELECT case_id FROM cases WHERE dataset_id=? AND dataset_version=?",
        (dataset_id, metadata.dataset_version),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"Reference dataset has no case: {dataset_id}")
    data_profiles = store.list_profiles(dataset_id, metadata.dataset_version)
    if [profile.level for profile in data_profiles] != ["l0", "l1", "l2", "l3"]:
        raise RuntimeError(f"Reference dataset must define exactly one L0-L3 profile: {dataset_id}")
    if settings.demo.data_profile not in {profile.profile_id for profile in data_profiles}:
        raise RuntimeError(
            f"Configured demo profile is not present in {dataset_id}: {settings.demo.data_profile}"
        )
    # Readiness is derived purely from each profile's visible sources; no
    # investigation is run here. AI investigation is triggered on demand.
    profiles = [
        ProfileComparisonItem(
            profile_id=profile.profile_id,
            level=profile.level,
            readiness=evaluate_data_readiness(
                profile,
                case_id=row["case_id"],
                tenant_id=settings.application.default_tenant,
                run_id=f"demo-{dataset_id}-{profile.level}",
            ),
            case=CaseReadModel(
                tenant_id=settings.application.default_tenant,
                case_id=row["case_id"],
                source_identity="demo-readiness",
                lifecycle_status="not_investigated",
            ),
        )
        for profile in data_profiles
    ]
    return DemoComparisonReadModel(
        dataset_id=dataset_id,
        dataset_version=metadata.dataset_version,
        reference_data_notice=(
            "本页面使用版本化合成参考数据，仅用于展示数据能力对研判质量的影响，"
            "不代表生产环境检出率或模型效果。"
        ),
        fixed_conditions={
            "case_id": row["case_id"],
            "content_digest": metadata.content_digest,
            "random_seed": metadata.random_seed,
            "default_focus_profile": settings.demo.data_profile,
            "judgment_planner": "structured-data-tool",
            "response_planner": "structured",
            "rag_adapter": "null",
        },
        profiles=profiles,
    )


def build_all_comparisons(settings: AppSettings) -> dict[str, DemoComparisonReadModel]:
    store = SQLiteReferenceDataStore(settings.demo.data_store_path)
    try:
        metadata = initialize_reference_demo(
            store,
            project_root=PROJECT_ROOT,
            tenant_id=settings.application.default_tenant,
        )
        return {
            dataset_id: run_demo_comparison(store=store, dataset_id=dataset_id, settings=settings)
            for dataset_id in metadata
        }
    finally:
        store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the controlled data-quality comparison demo")
    parser.add_argument("--database", help="Reference SQLite database path")
    parser.add_argument("--output", help="Write all comparison read models to this JSON file")
    parser.add_argument("--serve", action="store_true", help="Serve read-only comparison pages")
    args = parser.parse_args()
    settings = AppSettings.load(cli_overrides={"DEMO_DATA_STORE_PATH": args.database})
    print(format_effective_settings(settings), flush=True)
    comparisons = build_all_comparisons(settings)
    output = Path(args.output).resolve() if args.output else None
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {key: value.model_dump(mode="json") for key, value in comparisons.items()},
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    if args.serve:
        import uvicorn
        from .demo_runtime import DemoRunService

        app = create_app(
            InMemoryCaseReadStore(),
            InMemoryDemoComparisonStore(comparisons),
            DemoRunService(settings, project_root=PROJECT_ROOT),
        )
        uvicorn.run(app, host=settings.presentation.host, port=settings.presentation.port)
    else:
        summary = {
            key: [
                {
                    "profile": item.profile_id,
                    "answerable_questions": len(item.readiness.answerable_questions),
                    "verdict": item.case.judgment.verdict.level.value if item.case.judgment else None,
                }
                for item in comparison.profiles
            ]
            for key, comparison in comparisons.items()
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
