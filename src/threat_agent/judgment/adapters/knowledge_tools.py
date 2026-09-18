"""On-demand knowledge tools — split entries of the investigation scenario
service (target design section 5).

The split exists to raise trigger probability: each tool name matches a
concrete need during investigation instead of a generic "query knowledge".
Arguments stay business-semantic; scene and intent are fixed by the tool, so
the model can never name sources, retrieval parameters or authorization.
Results enter the model context with their category-level usage limitations
attached, and every consultation is recorded in the tool ledger.
"""

from __future__ import annotations

from typing import Any, Callable

from langchain_core.tools import StructuredTool

from ...contracts import (
    AttackTechniqueLookupInput,
    InterpretTelemetryFieldInput,
    JudgmentExperienceLookupInput,
    KnowledgeConsultation,
    KnowledgeConsultationContext,
    KnowledgeConsultationResult,
)
from ...contracts.investigation_tools import InvestigationToolLedger
from ..application.knowledge_baseline import record_consultation


def _invoke(
    service,
    ledger: InvestigationToolLedger,
    request: KnowledgeConsultation,
    *,
    entry: str,
    event_sink: Callable[..., None],
) -> dict[str, Any]:
    result: KnowledgeConsultationResult = service.consult_investigation(request)
    record_consultation(ledger, result, entry=entry)
    event_sink(
        "knowledge",
        f"知识咨询 {entry} 完成：{result.status}",
        {
            "node": "execute",
            "tool_name": entry,
            "entry": entry,
            "status": result.status,
            "consultation_id": result.consultation_id,
            "query_id": result.query_id,
            "sources": [
                {
                    "source_category": outcome.source_category,
                    "status": outcome.status,
                    "item_count": outcome.item_count,
                }
                for outcome in result.source_outcomes
            ],
            # 命中条目清单（标识+标题，不含正文）：运行页知识面板据此展示
            # "查了什么、命中了什么"；正文只在模型上下文与账本 item_refs 里。
            "items": [
                {
                    "knowledge_id": item.knowledge_id,
                    "version": item.version,
                    "source_category": item.source_category,
                    "title": item.title,
                }
                for item in result.items
            ],
        },
    )
    return result.model_dump(mode="json")


def knowledge_scenario_tools(
    service,
    ledger: InvestigationToolLedger,
    *,
    event_sink: Callable[..., None] | None = None,
) -> list[StructuredTool]:
    sink = event_sink or (lambda *_args, **_kwargs: None)

    def lookup_attack_technique(**arguments: Any) -> dict:
        request = AttackTechniqueLookupInput.model_validate(arguments)
        return _invoke(
            service,
            ledger,
            KnowledgeConsultation(
                scene="unknown_file_investigation",
                intent="attack_technique_lookup",
                context=KnowledgeConsultationContext(
                    verified_behaviors=list(request.behaviors)
                ),
            ),
            entry="lookup_attack_technique",
            event_sink=sink,
        )

    def interpret_telemetry_field(**arguments: Any) -> dict:
        request = InterpretTelemetryFieldInput.model_validate(arguments)
        return _invoke(
            service,
            ledger,
            KnowledgeConsultation(
                scene="unknown_file_investigation",
                intent="telemetry_interpretation",
                context=KnowledgeConsultationContext(
                    telemetry_field_ids=list(request.field_ids)
                ),
            ),
            entry="interpret_telemetry_field",
            event_sink=sink,
        )

    def consult_judgment_experience(**arguments: Any) -> dict:
        request = JudgmentExperienceLookupInput.model_validate(arguments)
        return _invoke(
            service,
            ledger,
            KnowledgeConsultation(
                scene="unknown_file_investigation",
                intent="judgment_experience_lookup",
                context=KnowledgeConsultationContext(
                    verified_behaviors=list(request.behaviors),
                    open_hypotheses=list(request.hypotheses),
                ),
            ),
            entry="consult_judgment_experience",
            event_sink=sink,
        )

    definitions = [
        (
            "lookup_attack_technique",
            AttackTechniqueLookupInput,
            lookup_attack_technique,
            "查询 ATT&CK 攻击技术知识：给出已观察到的行为（如计划任务持久化、固定间隔回连），"
            "返回技术映射、常见取证点与调查建议。结果仅作调查指引，不是案件证据。",
        ),
        (
            "interpret_telemetry_field",
            InterpretTelemetryFieldInput,
            interpret_telemetry_field,
            "解释告警/日志字段或告警类型的含义：给出字段名（如 netflow.session_reset_count）"
            "或告警类型标识，返回该遥测的语义、常见触发场景与误报来源。",
        ),
        (
            "consult_judgment_experience",
            JudgmentExperienceLookupInput,
            consult_judgment_experience,
            "查询人工研判经验：给出已验证行为与待验证假设，返回历史研判做法、"
            "取证顺序与注意事项。结果仅作调查指引，不是案件证据。",
        ),
    ]
    return [
        StructuredTool.from_function(
            func=handler,
            name=name,
            description=description,
            args_schema=schema,
        )
        for name, schema, handler, description in definitions
    ]
