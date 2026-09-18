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
    create_configured_checkpointer,
    initialize_state,
)
from ..case_management.application import evaluate_data_readiness
from ..contracts import (
    CaseReadModel,
    DemoComparisonReadModel,
    ProfileComparisonItem,
    ToolRuntimeContext,
)
from ..data_foundation.adapters import (
    SQLiteActivityStore, SQLiteInvestigationDataAdapter,
    SQLiteReferenceDataStore,
)
from ..data_foundation.application import initialize_reference_demo, reference_activity_store_path
from ..judgment import (
    InvestigationToolGateway,
    ReportGroundingValidator,
    ReportPublisher,
    ReportRepairCoordinator,
    StructuredReportComposer,
)
from ..presentation import InMemoryCaseReadStore
from ..presentation.api.routes import create_app
from ..knowledge import (
    NullKnowledgeSupplier,
    ReferenceKnowledgeAdapter,
    SecurityKnowledgeService,
)
from ..knowledge.adapters.attack_corpus import AttackCorpusSupplier
from ..knowledge.adapters.routing import RoutingSupplier
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
from .middleware_runtime import MiddlewareJudgmentRunner


CASE_STORIES = {
    "c2-malicious-reference": {
        "badge": "预置攻击 · 生产环境",
        "title": "未知程序伪装成系统更新服务，在支付服务器上建立远控通道",
        "lead": "安全设备最初只发现 /tmp/.cache/sysupd 这个未知 ELF。完整事件显示，它通过 SSH 会话以 root 身份执行，随后外联、创建系统服务并执行远程命令。",
        "asset": "payment-api-prod-01",
        "asset_meta": "生产支付接口 · 核心资产",
        "risk": "攻击仍具备远程控制与重启后驻留能力",
        "scope": "当前证据仅覆盖 server-01，相关身份和横向影响尚未排查",
        "steps": [
            ("03:17", "进入主机", "SSH 会话启动 bash，为后续执行提供入口"),
            ("03:20", "恶意执行", "bash 以 root 身份运行 /tmp/.cache/sysupd"),
            ("03:21", "外联与驻留", "连接 203.0.113.50:443，同时写入并启用 sysupd.service"),
            ("03:24", "远程控制", "收到网络输入后拉起 /bin/sh，执行 id 与 uname -a"),
        ],
    },
    "c2-benign-reference": {
        "badge": "预置对照 · 测试环境",
        "title": "监控程序表现出相似行为，但完整数据证明它是批准的合法软件",
        "lead": "安全设备最初只发现 /opt/vendor/monitor-agent 这个未知 ELF。完整事件显示，它由 systemd 正常启动，只访问批准的厂商端点，并具有可信软件包来源。",
        "asset": "monitoring-test-02",
        "asset_meta": "监控验证系统 · 低关键度资产",
        "risk": "未发现恶意活动，行为与批准的监控服务一致",
        "scope": "软件签名、仓库来源与 CMDB 端点基线均已完成核验",
        "steps": [
            ("03:20", "服务启动", "systemd 启动 vendor-monitor 守护进程"),
            ("03:20", "健康检查", "程序调用 uptime 获取主机运行状态"),
            ("03:21", "监控心跳", "周期连接批准的厂商监控服务"),
            ("03:25", "身份核验", "软件包签名、可信仓库和 CMDB 基线共同完成反证"),
        ],
    },
}

def build_knowledge_service(settings: AppSettings) -> SecurityKnowledgeService:
    """按管理面配置（首期为配置项）组装知识能力服务；Agent 运行中不可改。

    adapter=attack（Feature 18）：ATT&CK 真实语料供应方接管 attack_technique
    源，其余四类继续走参考适配器（真实数据到位前的占位与演练夹具）。"""

    knowledge = settings.knowledge
    if knowledge.adapter == "attack":
        adapter = RoutingSupplier(
            routes={
                "attack_technique": AttackCorpusSupplier(
                    corpus_path=knowledge.attack_corpus_path
                )
            },
            default=ReferenceKnowledgeAdapter(profile=knowledge.reference_profile),
        )
    elif knowledge.adapter == "reference":
        adapter = ReferenceKnowledgeAdapter(profile=knowledge.reference_profile)
    else:
        adapter = NullKnowledgeSupplier()
    return SecurityKnowledgeService(adapter, timeout_seconds=knowledge.timeout_seconds)


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


class ObservableReportComposer:
    """Emit workflow events around draft composition and rejudgment.

    Wraps the delegate so report-phase model calls report token usage and
    latency like the planning loop does — otherwise run-level token totals
    silently omit the heaviest single call."""

    def __init__(self, delegate, emit: EventSink):
        self.delegate = delegate
        self.emit = emit
        self.model_name = getattr(delegate, "model_name", "unknown")

    @staticmethod
    def _usage(draft) -> dict:
        meta = getattr(draft, "usage_metadata", None) or {}
        return {k: int(v) for k, v in meta.items() if isinstance(v, (int, float))}

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


def _attach_trace(model, trace_handler) -> None:
    if trace_handler is not None:
        model.callbacks = [trace_handler]


class ReferenceRunAssembly:
    """Per-run wiring of the middleware runtime.

    Everything is derived from settings plus the reference store, so the debug
    access layer can rebuild an identical graph for checkpoint history and
    resume after the original execution thread is gone.
    """

    def __init__(
        self,
        *,
        graph: CaseGraph,
        state,
        tenant_id: str,
        activity_store: SQLiteActivityStore,
        run_id: str,
        dataset_id: str | None = None,
        dataset_version: str | None = None,
        profile=None,
    ):
        self.graph = graph
        self.state = state
        self.tenant_id = tenant_id
        self.activity_store = activity_store
        self.dataset_id = dataset_id
        self.dataset_version = dataset_version
        self.profile = profile
        self.run_id = run_id

    def close(self) -> None:
        self.activity_store.close()


def assemble_investigation_run(
    activity_store: SQLiteActivityStore,
    *,
    state,
    settings: AppSettings,
    emit: EventSink | None = None,
    run_id: str,
    trace_handler=None,
    response_context_port=None,
    visible_sources=None,
) -> ReferenceRunAssembly:
    """Settings-only assembly of the middleware runtime for one investigation
    state — shared by reference-dataset runs and real alert runs."""

    emit = emit or (lambda _kind, _message, _details=None: None)
    investigation_data = SQLiteInvestigationDataAdapter(
        activity_store, visible_sources=visible_sources
    )
    tenant_id = settings.application.default_tenant
    boundary_policy = SingleHostBoundaryPolicy(
        tenant_id=tenant_id,
        case_id=state.case_id,
        run_id=run_id,
    )
    gateway = InvestigationToolGateway(
        investigation_data,
        boundary_policy,
        event_sink=emit,
    )
    judgment_model = build_judgment_model(settings)
    summarizer_model = build_judgment_model(settings)
    report_model = build_report_model(settings)
    response_model = build_response_model(settings)
    from .middleware_runtime import LlmEventBridge

    # Report and advisory calls get their own bridges so their token usage and
    # latency land in the ledger exactly like the planning loop's.
    report_model.callbacks = [LlmEventBridge(emit, phase="judgment_report", node="compose")]
    response_model.callbacks = [LlmEventBridge(emit, phase="response_advisory", node="advise")]
    for model in (judgment_model, summarizer_model):
        _attach_trace(model, trace_handler)
    report_composer = ObservableReportComposer(
        StructuredReportComposer(report_model, emit, tenant_id=tenant_id),
        emit,
    )
    response_planner = ObservableResponsePlanner(
        StructuredResponsePlanner(response_model, emit), emit
    )
    report_publisher = ObservableReportPublisher(
        ReportPublisher(
            tenant_id=tenant_id,
            run_id=run_id,
            model_name=report_composer.model_name,
        ),
        emit,
    )
    judgment_stage = MiddlewareJudgmentRunner(
        model=judgment_model,
        summarizer_model=summarizer_model,
        gateway=gateway,
        boundary_policy=boundary_policy,
        context=ToolRuntimeContext(
            tenant_id=tenant_id,
            case_id=state.case_id,
            run_id=run_id,
            scope=state.scope,
        ),
        ledger=state.tool_ledger,
        case_budget=state.budget,
        report_composer=report_composer,
        report_coordinator=ReportRepairCoordinator(
            report_composer, ReportGroundingValidator(), event_sink=emit,
        ),
        report_publisher=report_publisher,
        knowledge_service=build_knowledge_service(settings),
        emit=emit,
        context_window_tokens=settings.judgment_model.context_window_tokens,
        recursion_limit=settings.graph.recursion_limit,
    )
    response_graph = ResponseGraph(
        response_planner,
        knowledge_service=build_knowledge_service(settings),
        response_context_port=response_context_port,
        max_iterations=settings.response_budget.max_iterations,
        recursion_limit=settings.graph.recursion_limit,
    )
    graph = CaseGraph(
        judgment_stage,
        checkpointer=create_configured_checkpointer(
            settings.checkpoint.backend, settings.checkpoint.path
        ),
        response_graph=response_graph,
        recursion_limit=settings.graph.recursion_limit,
    )
    return ReferenceRunAssembly(
        graph=graph,
        state=state,
        tenant_id=tenant_id,
        activity_store=activity_store,
        run_id=run_id,
    )


def assemble_reference_run(
    store: SQLiteReferenceDataStore,
    *,
    dataset_id: str,
    dataset_version: str | None = None,
    case_id: str,
    profile_id: str,
    settings: AppSettings,
    emit: EventSink | None = None,
    run_id: str,
    trace_handler=None,
) -> ReferenceRunAssembly:
    emit = emit or (lambda _kind, _message, _details=None: None)
    dataset_version = dataset_version or settings.demo.dataset_version
    profile = store.get_profile(dataset_id, dataset_version, profile_id)
    raw = store.get_case_input(dataset_id, dataset_version, case_id)
    state = initialize_state(
        raw, lookback_hours=settings.application.investigation_lookback_hours
    )
    state.budget.max_iterations = settings.judgment_budget.max_iterations
    state.budget.max_tool_calls = settings.judgment_budget.max_tool_calls
    state.budget.max_report_rejudgments = settings.judgment_budget.max_report_rejudgments
    state.raw_input["run_id"] = run_id

    profile = store.get_profile(dataset_id, dataset_version, profile_id)
    raw = store.get_case_input(dataset_id, dataset_version, case_id)
    state = initialize_state(
        raw, lookback_hours=settings.application.investigation_lookback_hours
    )
    state.budget.max_iterations = settings.judgment_budget.max_iterations
    state.budget.max_tool_calls = settings.judgment_budget.max_tool_calls
    state.budget.max_report_rejudgments = settings.judgment_budget.max_report_rejudgments
    state.raw_input["run_id"] = run_id
    settings.require_models()
    # create_agent executes tool calls on worker threads; the activity store
    # must accept sequential cross-thread use (same posture as the test
    # harness and the runtime store).
    activity_store = SQLiteActivityStore(
        reference_activity_store_path(store.path, dataset_id), check_same_thread=False
    )
    assembly = assemble_investigation_run(
        activity_store,
        state=state,
        settings=settings,
        emit=emit,
        run_id=run_id,
        trace_handler=trace_handler,
        response_context_port=ReferenceResponseContextAdapter(
            store,
            dataset_id=dataset_id,
            dataset_version=dataset_version,
            profile=profile,
        ),
        visible_sources=set(profile.visible_sources),
    )
    assembly.dataset_id = dataset_id
    assembly.dataset_version = dataset_version
    assembly.profile = profile
    return assembly

    return ReferenceRunAssembly(
        graph=graph,
        state=state,
        tenant_id=tenant_id,
        activity_store=activity_store,
        dataset_id=dataset_id,
        dataset_version=dataset_version,
        profile=profile,
        run_id=run_id,
    )


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
    trace_handler=None,
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
    effective_run_id = run_id or f"demo-{dataset_id}-trace"
    assembly = assemble_reference_run(
        store,
        dataset_id=dataset_id,
        dataset_version=dataset_version,
        case_id=case_id,
        profile_id=profile_id,
        settings=settings,
        emit=emit,
        run_id=effective_run_id,
        trace_handler=trace_handler,
    )
    try:
        state = assembly.state
        tenant_id = assembly.tenant_id
        graph = assembly.graph
        profile = assembly.profile
        emit("graph", "AI 已开始调查：正在建立案件上下文", {
            "node": "intake",
            "profile": profile.profile_id,
            "planner_mode": "llm",
            "orchestration": "framework_middleware",
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
    finally:
        assembly.close()


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
            "rag_adapter": settings.knowledge.adapter,
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

        from .workbench_bindings import (
            build_approval_service,
            build_debug_service,
            build_event_service,
            build_settings_overview,
            build_knowledge_overview,
            build_run_service,
        )

        run_service = build_run_service(settings, project_root=PROJECT_ROOT)
        app = create_app(
            InMemoryCaseReadStore(),
            None,
            run_service,
            build_approval_service(settings, run_service),
            build_debug_service(settings, run_service)
            if settings.workbench.debug_enabled
            else None,
            build_knowledge_overview(settings),
            build_event_service(settings),
            build_settings_overview(settings),
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
