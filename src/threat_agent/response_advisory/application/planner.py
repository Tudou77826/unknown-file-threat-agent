from __future__ import annotations

import json
from typing import Any, Callable, Protocol

from ...contracts import (
    JudgmentResult,
    KnowledgeConsultationResult,
    ResponseContext,
)
from ...shared.llm import invoke_llm, structured_output_method
from ..domain.models import ResponseProposal


class ResponsePlanner(Protocol):
    def propose(
        self,
        judgment: JudgmentResult,
        knowledge: KnowledgeConsultationResult | None,
        validation_errors: list[str],
        response_context: ResponseContext | None = None,
    ) -> ResponseProposal: ...


# Few-shot exemplar 1: a high-impact containment action done properly. Weaker
# models imitate the shape — impact narration, a conservative approval class
# and rollback steps — instead of having to recognize "high risk" on their own.
_EXAMPLE_HIGH_IMPACT = {
    "actions": [
        {
            "action_id": "act-isolate",
            "action_type": "isolate_host",
            "target_refs": ["server-01"],
            "rationale": "证据显示 PID 1234 通过 /tmp/.cache/sysupd 持久化并每分钟回连 203.0.113.50:443（引用 judgment 中的连接与 socket 活动），隔离主机是切断 C2 通道最直接的手段",
            "judgment_refs": ["activity-raw-net-001", "activity-raw-net-004", "activity-raw-socket-out"],
            "preconditions": ["确认 203.0.113.50 不承载任何合法业务", "通知业务负责人并约定窗口"],
            "expected_impact": "隔离 server-01 将中断其上运行的监控采集与定时备份约 30-60 分钟；不会丢失数据，但备份延迟一个周期；若判断有误，恢复成本仅为重新接入网络并验证服务，属可逆操作",
            "approval_class": "security_lead",
            "rollback_steps": ["解除网络隔离策略", "验证主机恢复内网连通", "观察 15 分钟确认无异常回连"],
            "verification_steps": ["确认不再出现到 203.0.113.50 的新连接", "复查 sysupd.service 已停止且未自启"],
        }
    ],
    "missing_context": ["缺少 203.0.113.50 的威胁情报归属"],
    "residual_risk": ["样本可能已在其他主机落地，隔离单机不能阻断横向扩散"],
}

# Few-shot exemplar 2: conservative advice when the verdict is not reliable.
_EXAMPLE_CONSERVATIVE = {
    "actions": [
        {
            "action_id": "act-collect",
            "action_type": "collect_more_data",
            "target_refs": ["server-02"],
            "rationale": "当前证据不足以定性，先补齐进程与网络遥测再研判",
            "judgment_refs": ["evidence-ref-sample-1"],
            "preconditions": ["确认采集代理在线"],
            "expected_impact": "只读采集，对业务无影响",
            "approval_class": "none",
            "rollback_steps": [],
            "verification_steps": ["确认新增数据可被查询接口返回"],
        },
        {
            "action_id": "act-review",
            "action_type": "manual_review",
            "target_refs": ["server-02"],
            "rationale": "结论可靠性不足，需要人工复核告警原文与采样样本",
            "judgment_refs": ["evidence-ref-sample-1"],
            "preconditions": ["安全值班同事可接手"],
            "expected_impact": "无系统影响，仅占用人工复核时间",
            "approval_class": "none",
            "rollback_steps": [],
            "verification_steps": ["复核结论回填到工单"],
        }
    ],
    "missing_context": ["告警样本本体尚未取得"],
    "residual_risk": ["复核期间样本可能继续运行"],
}


class StructuredResponsePlanner:
    """Use a chat model's structured-output capability for response planning."""

    def __init__(self, model: Any, event_sink: Callable | None = None):
        self.model = model
        self.event_sink = event_sink or (lambda _kind, _message, _details=None: None)
        self.structured_model = model.with_structured_output(
            ResponseProposal, method=structured_output_method(model)
        )
        self.system_prompt = (
            "Return one JSON object matching the ResponseProposal schema. "
            "The top-level keys are actions, missing_context and residual_risk; "
            "do not wrap the object in ResponsePlan or add contract metadata. "
            "Return no more than three actions. "
            "Write all natural-language fields in Simplified Chinese. "
            "Create a response advisory plan. Judgment facts are read-only. "
            "Every action must include rationale, preconditions, expected impact, "
            "approval class, rollback steps, verification steps, and resolvable "
            "judgment references. approval_class must be exactly one of none, operator, "
            "security_lead, business_owner. Never claim that an action "
            "was executed. "
            "Every action must read like an operational work card, not a slogan: "
            "rationale cites the judgment evidence and explains the causal chain; "
            "expected_impact is a real impact narration — what the action touches, "
            "the business/availability cost, the blast radius if the judgment is "
            "wrong, and whether it is reversible. "
            "High-impact discipline: any action that isolates, blocks, quarantines, "
            "terminates or deletes — regardless of how you name it — must carry "
            "approval_class of operator or above and non-empty rollback_steps, "
            "and its expected_impact must state the availability cost. "
            # 处置知识并列呈现规则（设计 §6-3）：知情权优先，不按来源取舍
            "The knowledge object is merged disposal knowledge: every qualified item "
            "from every source is present, labeled with source_category and its "
            "category_limitations. Do not drop, downweight or hide any item because "
            "of its source; weigh items by relevance only. When multiple references "
            "disagree, present them side by side in your rationale, state that "
            "multiple references exist, and give at most one recommendation with "
            "reasons — never silently discard a reference. When two same-level "
            "policies conflict, present both, mark the conflict explicitly, and "
            "require human confirmation via approval_class of security_lead or "
            "above. Knowledge presentation never weakens the final constraints: "
            "every action must still pass asset-condition checks, disposal policy "
            "and the approval flow. Cite knowledge you relied on in "
            "knowledge_refs using each item's exact "
            "knowledge_id@version#chunk_id reference. "
            "If judgment.publication_status is 'fallback', the verdict did not "
            "survive grounding validation: use ONLY the action types "
            "re_run_analysis, collect_more_data or manual_review. Any other "
            "action type will be rejected. "
            "Follow the exemplar matching the situation. "
            "Exemplar A — malicious verdict, high-impact containment done properly: "
            + json.dumps(_EXAMPLE_HIGH_IMPACT, ensure_ascii=False)
            + " "
            "Exemplar B — insufficient/fallback verdict, conservative advice only: "
            + json.dumps(_EXAMPLE_CONSERVATIVE, ensure_ascii=False)
            + " "
            "JSON schema: "
            + json.dumps(ResponseProposal.model_json_schema(), ensure_ascii=False)
        )

    def propose(
        self,
        judgment: JudgmentResult,
        knowledge: KnowledgeConsultationResult | None,
        validation_errors: list[str],
        response_context: ResponseContext | None = None,
    ) -> ResponseProposal:
        payload = {
            "judgment": judgment.model_dump(mode="json"),
            "knowledge": knowledge.model_dump(mode="json") if knowledge else None,
            "validation_errors": validation_errors,
            "response_context": (
                response_context.model_dump(mode="json") if response_context else None
            ),
        }
        messages = [
            {
                "role": "system",
                "content": self.system_prompt,
            },
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ]

        def invoke_once() -> ResponseProposal:
            return ResponseProposal.model_validate(self.structured_model.invoke(messages))

        def build_feedback(_attempt: int, error: Exception):
            return {
                "role": "user",
                "content": (
                    "The previous JSON did not match ResponseProposal. Return only a "
                    "corrected JSON object with the exact schema and enum values. "
                    f"Validation error: {str(error)[:1200]}"
                ),
            }

        def on_attempt(attempt: int) -> None:
            self.event_sink("model_input", "处置建议模型输入", {
                "phase": "response_advisory",
                "attempt": attempt,
                "messages": messages,
            })

        def on_output(_attempt: int, output: ResponseProposal) -> None:
            self.event_sink("model_output", "处置建议模型输出", {
                "phase": "response_advisory",
                "output": output.model_dump(mode="json"),
            })

        def on_failure(attempt: int, error: Exception, kind: str) -> None:
            self.event_sink(
                "model_output",
                "处置建议模型输出校验失败" if kind == "parse" else "处置建议模型调用失败",
                {
                    "phase": "response_advisory",
                    "attempt": attempt,
                    "error_type": type(error).__name__,
                    "error_message": str(error),
                },
            )

        return invoke_llm(
            invoke_once,
            messages=messages,
            build_feedback=build_feedback,
            on_attempt=on_attempt,
            on_output=on_output,
            on_failure=on_failure,
            parse_max_attempts=3,
        )
