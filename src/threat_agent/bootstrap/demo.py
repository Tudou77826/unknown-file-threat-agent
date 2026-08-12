from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable

from ..case_management import CaseGraph, build_case_read_model, create_memory_checkpointer, initialize_state
from ..case_management.application import evaluate_data_readiness
from ..contracts import DemoComparisonReadModel, ProfileComparisonItem
from ..data_foundation.adapters import SQLiteEvidenceQueryAdapter, SQLiteReferenceDataStore
from ..data_foundation.application import initialize_reference_demo
from ..judgment import DeterministicPlanner, JudgmentGraph, StructuredJudgmentPlanner, ToolRegistry
from ..presentation import InMemoryCaseReadStore, InMemoryDemoComparisonStore
from ..presentation.api.routes import create_app
from ..response_advisory import DeterministicResponsePlanner, ResponseGraph, StructuredResponsePlanner
from ..response_advisory.adapters import ReferenceResponseContextAdapter
from .settings import AppSettings, PROJECT_ROOT, build_judgment_model, build_response_model


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


class ObservableEvidenceQuery:
    def __init__(self, delegate, emit: EventSink):
        self.delegate = delegate
        self.emit = emit

    def query_evidence(self, query):
        self.emit("tool", f"查询 {query.domain} 数据", {
            "query_id": query.query_id,
            "evidence_types": query.evidence_types,
        })
        result = self.delegate.query_evidence(query)
        self.emit("evidence", f"数据查询返回 {len(result.evidence)} 条记录", {
            "status": result.status.value,
            "domain": query.domain,
            "evidence_ids": [item.evidence_id for item in result.evidence[:8]],
        })
        return result


class ObservableJudgmentPlanner:
    def __init__(self, delegate, emit: EventSink):
        self.delegate = delegate
        self.emit = emit

    def plan(self, state):
        self.emit("thinking", "研判模型正在选择下一步调查动作", {
            "iteration": state.budget.iterations_used,
            "open_gaps": [gap.gap_id for gap in state.evidence_gaps if gap.status == "open"][:8],
        })
        action = self.delegate.plan(state)
        decision = state.planner_decisions[-1] if state.planner_decisions else None
        self.emit("decision", f"研判模型选择：{action.action_type}", {
            "tool_name": getattr(action, "tool_name", None),
            "objective": action.objective,
            "decision_summary": decision.decision_summary if decision else action.objective,
            "fallback_used": decision.fallback_used if decision else False,
        })
        return action

    def repair(self, state, invalid_action, validation_error):
        self.emit("repair", "结构化动作未通过校验，研判模型正在修复", {
            "validation_error": validation_error,
        })
        return self.delegate.repair(state, invalid_action, validation_error)


class ObservableResponsePlanner:
    def __init__(self, delegate, emit: EventSink):
        self.delegate = delegate
        self.emit = emit

    def propose(self, judgment, knowledge, validation_errors, response_context=None):
        level = judgment.verdict.level.value
        self.emit("verdict", f"研判结论：{VERDICT_LABEL_ZH.get(level, level)}", {
            "verdict": level,
            "summary": VERDICT_SUMMARY_ZH.get(level, judgment.verdict.summary),
            "supporting_refs": judgment.verdict.supporting_refs,
            "contradicting_refs": judgment.verdict.contradicting_refs,
        })
        self.emit("thinking", "处置模型正在结合研判结果与资产上下文生成建议", {
            "verdict": judgment.verdict.level.value,
            "validation_errors": validation_errors,
        })
        proposal = self.delegate.propose(
            judgment, knowledge, validation_errors, response_context
        )
        self.emit("response", f"处置模型生成 {len(proposal.actions)} 项建议", {
            "action_types": [item.action_type for item in proposal.actions],
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
    mode: str = "deterministic",
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
    state = initialize_state(raw)
    state.budget.max_iterations = settings.judgment_budget.max_iterations
    state.budget.max_tool_calls = settings.judgment_budget.max_tool_calls
    state.budget.max_scope_expansions = settings.judgment_budget.max_scope_expansions
    state.budget.max_repair_actions = settings.judgment_budget.max_repair_actions
    state.budget.max_verdict_repairs = settings.judgment_budget.max_verdict_repairs
    base_query_port = SQLiteEvidenceQueryAdapter(
        store,
        dataset_id=dataset_id,
        dataset_version=dataset_version,
        profile=profile,
    )
    query_port = ObservableEvidenceQuery(base_query_port, emit) if mode == "llm" else base_query_port
    registry = ToolRegistry(
        query_port,
        query_default_limit=settings.evidence_query.default_limit,
        query_max_limit=settings.evidence_query.max_limit,
    )
    if mode == "llm":
        settings.require_models()
        judgment_planner = ObservableJudgmentPlanner(
            StructuredJudgmentPlanner(build_judgment_model(settings), registry), emit
        )
        response_planner = ObservableResponsePlanner(
            StructuredResponsePlanner(build_response_model(settings)), emit
        )
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
    effective_run_id = run_id or f"demo-{dataset_id}-{profile.level}"
    emit("graph", "LangGraph 调查流程已启动", {
        "profile": profile.profile_id,
        "planner_mode": mode,
    })
    result = graph.start(state, tenant_id="demo", run_id=effective_run_id)
    while (request := _interrupt_value(result)) is not None:
        if request.get("kind") == "scope_approval":
            result = graph.resume_scope(
                tenant_id="demo", case_id=state.case_id, run_id=effective_run_id,
                approved=False, approved_by="reference-demo-policy",
            )
        elif request.get("kind") == "response_approval":
            result = graph.resume_response(
                tenant_id="demo", case_id=state.case_id, run_id=effective_run_id,
                approved=False, approved_by="reference-demo-policy",
            )
        else:
            raise RuntimeError(f"Unsupported graph interrupt: {request!r}")
    completed = type(state).model_validate(result["investigation"])
    read_model = build_case_read_model(
        completed,
        tenant_id="demo",
        lifecycle_status=str(result["lifecycle_status"]),
        judgment=result.get("judgment_result"),
        response_plan=result.get("response_plan"),
        approval_status=result.get("approval_status"),
    )
    if mode == "llm" and read_model.judgment is not None:
        localize_verdict(read_model.judgment)
    readiness = evaluate_data_readiness(
        completed, profile, tenant_id="demo", run_id=effective_run_id
    )
    level = read_model.judgment.verdict.level.value
    emit("result", f"案件处理完成：{VERDICT_LABEL_ZH.get(level, level)}", {
        "summary": read_model.judgment.verdict.summary,
        "fact_count": len(read_model.facts),
        "finding_count": len(read_model.findings),
        "answerable_questions": len(readiness.answerable_questions),
    })
    return ProfileComparisonItem(
        profile_id=profile.profile_id,
        level=profile.level,
        readiness=readiness,
        case=read_model,
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
    profiles = [
        run_demo_profile(
            store,
            dataset_id=dataset_id,
            dataset_version=metadata.dataset_version,
            case_id=row["case_id"],
            profile_id=profile.profile_id,
            settings=settings,
            mode="deterministic",
        )
        for profile in data_profiles
    ]
    previous_facts: set[str] = set()
    previous_findings: set[str] = set()
    enriched: list[ProfileComparisonItem] = []
    for item in profiles:
        fact_ids = {str(value["fact_id"]) for value in item.case.facts}
        finding_ids = {str(value["finding_id"]) for value in item.case.findings}
        enriched.append(item.model_copy(update={
            "new_fact_ids": sorted(fact_ids - previous_facts),
            "new_finding_ids": sorted(finding_ids - previous_findings),
        }))
        previous_facts = fact_ids
        previous_findings = finding_ids
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
            "judgment_planner": "deterministic",
            "response_planner": "deterministic",
            "rag_adapter": "null",
        },
        profiles=enriched,
    )


def build_all_comparisons(settings: AppSettings) -> dict[str, DemoComparisonReadModel]:
    store = SQLiteReferenceDataStore(settings.demo.data_store_path)
    try:
        metadata = initialize_reference_demo(store, project_root=PROJECT_ROOT)
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
