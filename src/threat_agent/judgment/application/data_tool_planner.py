from __future__ import annotations

import json
from typing import Any, Callable, Literal

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from pydantic import Field

from ...contracts import (
    AssetActivitiesInput,
    CalculateActivityMetricsInput,
    ExploreEntityInput,
    FileActivitiesInput,
    GetRawRecordsInput,
    NetworkActivitiesInput,
    PackageActivitiesInput,
    ProcessActivitiesInput,
    ServiceActivitiesInput,
    SocketActivitiesInput,
)
from ...shared import StrictModel
from ..domain.models import (
    DataToolRequest,
    FinishRequest,
    InvestigationAction,
    InvestigationState,
    ScopeRequest,
)
from .native_tool_calling import (
    FinishInvestigationInput,
    RequestScopeExpansionInput,
    build_native_tools,
    parse_tool_call,
    serialize_messages,
)


class DataToolSelection(StrictModel):
    """Legacy contract retained for stored events; online planning uses native tool calls."""

    action: Literal[
        "query_process_activities", "query_network_activities", "query_socket_activities",
        "query_file_activities", "query_service_activities", "query_package_activities",
        "query_asset_activities", "explore_entity", "get_raw_records",
        "calculate_activity_metrics", "request_scope_expansion", "finish_investigation",
    ]
    objective: str = Field(default="执行下一步受控数据调查", min_length=10)
    arguments: dict[str, Any] = Field(default_factory=dict)
    scope_request: dict[str, Any] | None = None


def investigation_tools() -> list:
    """Return the exact schemas registered with the chat model.

    Query tools are split by activity domain: each tool's name fixes the
    domain, and its schema exposes only that domain's fields.
    """

    definitions = [
        ("query_process_activities", ProcessActivitiesInput,
         "查询进程活动：进程创建/执行/终止、父子关系、可执行文件与命令行。"),
        ("query_network_activities", NetworkActivitiesInput,
         "查询网络活动：进程发起/接受的连接、目标端点和协议。"),
        ("query_socket_activities", SocketActivitiesInput,
         "查询 socket 活动：进程的收发字节与 socket 会话。"),
        ("query_file_activities", FileActivitiesInput,
         "查询文件活动：创建、写入、重命名、删除、执行和读取。"),
        ("query_service_activities", ServiceActivitiesInput,
         "查询服务活动：systemd 等服务的定义、启用、启动与停止。"),
        ("query_package_activities", PackageActivitiesInput,
         "查询软件包活动：包归属、安装、签名与文件关联。"),
        ("query_asset_activities", AssetActivitiesInput,
         "查询资产活动：主机环境、业务关键度、负责人与批准上下文。"),
        ("explore_entity", ExploreEntityInput,
         "读取一个平台实体的身份、已解析/候选关系及时间线。entity_ref 必须来自案件或先前工具结果。"),
        ("get_raw_records", GetRawRecordsInput,
         "读取本次运行中已返回活动对应的原始记录。"),
        ("calculate_activity_metrics", CalculateActivityMetricsInput,
         "对本次运行已返回的活动执行进程树、连接模式、传输汇总或文件变更等确定性计算。"),
        ("request_scope_expansion", RequestScopeExpansionInput,
         "发现当前 Scope 外的相关主机且有证据引用时，发起范围扩大审批；本工具不直接扩大权限。"),
        ("finish_investigation", FinishInvestigationInput,
         "现有证据足以形成结论、继续查询没有信息增益或预算将耗尽时，结束调查并生成报告。"),
    ]
    return build_native_tools(definitions)


class StructuredDataToolPlanner:
    """Native OpenAI-compatible tool-calling planner controlled by JudgmentGraph."""

    uses_data_tools = True

    def __init__(self, model: Any, event_sink: Callable | None = None):
        self.tools = investigation_tools()
        self.bound_model = model.bind_tools(
            self.tools,
            tool_choice="required",
            strict=True,
            parallel_tool_calls=False,
            extra_body={"thinking": {"type": "disabled"}},
        )
        self.event_sink = event_sink or (lambda _kind, _message, _details=None: None)
        self.system_prompt = (
            "你是未知文件安全调查的取证规划器。根据案件证据和历次工具返回，每轮只调用一个已注册工具。"
            "工具参数必须严格遵循已注册 JSON Schema，不要自行创造字段。"
            "租户、案件、run_id 和授权 Scope 由系统注入，不得作为工具参数提交。"
            "空结果只代表该次查询在执行边界内返回零条，不能据此断言行为没有发生。"
            "候选关系只能用于继续调查，不能当作已确认事实。"
            "host_refs 必须使用 authorized_scope.host_ids 中的原始值，例如 server-01，不要添加 host: 前缀。"
            "explore_entity 只接受先前数据工具结果中出现的平台 entity_id，不要直接使用案件实体 ID。"
            "当进一步查询没有信息增益时调用 finish_investigation。"
        )

    def plan(self, state: InvestigationState) -> InvestigationAction:
        forced_finish = self._convergence_guard(state)
        if forced_finish is not None:
            return forced_finish
        messages = self._messages(state)
        self.event_sink("model_input", "研判模型输入", {
            "phase": "judgment_planning",
            "iteration": state.budget.iterations_used,
            "messages": serialize_messages(messages),
            "registered_tools": [
                {"name": tool.name, "description": tool.description,
                 "parameters": tool.args_schema.model_json_schema()}
                for tool in self.tools
            ],
        })
        try:
            response = self.bound_model.invoke(messages)
        except Exception as error:
            self.event_sink("model_output", "研判模型调用失败", {
                "phase": "judgment_planning",
                "iteration": state.budget.iterations_used,
                "error_type": type(error).__name__,
                "error_message": str(error),
            })
            raise
        if not isinstance(response, AIMessage):
            response = AIMessage(content=getattr(response, "content", str(response)))
        self.event_sink("model_output", "研判模型输出", {
            "phase": "judgment_planning",
            "iteration": state.budget.iterations_used,
            "content": response.content,
            "tool_calls": response.tool_calls,
            "response_metadata": response.response_metadata,
            "usage_metadata": response.usage_metadata,
            "additional_kwargs": response.additional_kwargs,
            "invalid_tool_calls": response.invalid_tool_calls,
        })
        if not response.tool_calls:
            return self._finish(state, "模型未请求新的数据工具，使用现有调查结果生成研判报告")
        name, arguments, call_id = parse_tool_call(response)
        if not call_id:
            call_id = f"tool-call-{state.budget.iterations_used}"
        call = response.tool_calls[0]
        if name in {
            "query_process_activities", "query_network_activities", "query_socket_activities",
            "query_file_activities", "query_service_activities", "query_package_activities",
            "query_asset_activities", "explore_entity", "get_raw_records", "calculate_activity_metrics",
        }:
            return DataToolRequest(
                tool_name=name,
                objective=self._objective(name),
                arguments=arguments,
                tool_call_id=call_id,
                model_message={
                    "content": response.content,
                    "tool_call": call,
                    "additional_kwargs": response.additional_kwargs,
                    "response_metadata": response.response_metadata,
                    "usage_metadata": response.usage_metadata,
                },
            )
        if name == "request_scope_expansion":
            return ScopeRequest(**arguments)
        if name == "finish_investigation":
            return FinishRequest(**arguments)
        raise ValueError(f"Model requested an unregistered tool: {name}")

    def repair(self, state, invalid_action, validation_error):
        self.event_sink("tool_message", "工具调用校验失败", {
            "phase": "judgment_planning",
            "tool_call_id": getattr(invalid_action, "tool_call_id", None),
            "tool_name": getattr(invalid_action, "tool_name", None),
            "error": validation_error,
        })
        return self.plan(state)

    def _messages(self, state: InvestigationState) -> list[Any]:
        context = {
            "case_id": state.case_id,
            "authorized_scope": state.scope.model_dump(mode="json"),
            "entities": [item.model_dump(mode="json") for item in state.entities],
            "upstream_evidence": [item.model_dump(mode="json") for item in state.evidence],
            "open_questions": [
                {"gap_id": item.gap_id, "question": item.question, "status": item.status}
                for item in state.evidence_gaps if item.status != "resolved"
            ],
            "budget": state.budget.model_dump(mode="json"),
        }
        messages: list[Any] = [
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=json.dumps(context, ensure_ascii=False)),
        ]
        for trace in state.tool_ledger.traces[-12:]:
            call_id = trace.tool_call_id or f"trace-{trace.sequence}"
            messages.append(AIMessage(content=trace.model_message.get("content", ""), tool_calls=[{
                "name": trace.tool_name,
                "args": trace.arguments,
                "id": call_id,
                "type": "tool_call",
            }], additional_kwargs=dict(trace.model_message.get("additional_kwargs") or {}),
                response_metadata=dict(trace.model_message.get("response_metadata") or {})))
            messages.append(ToolMessage(
                content=json.dumps(trace.result, ensure_ascii=False),
                tool_call_id=call_id,
                name=trace.tool_name,
                status="error" if trace.result_type == "ToolError" else "success",
            ))
        return messages

    @staticmethod
    def _objective(name: str) -> str:
        return {
            "query_process_activities": "查询进程活动并获取可引用数据对象",
            "query_network_activities": "查询网络活动并获取可引用数据对象",
            "query_socket_activities": "查询 socket 活动并获取可引用数据对象",
            "query_file_activities": "查询文件活动并获取可引用数据对象",
            "query_service_activities": "查询服务活动并获取可引用数据对象",
            "query_package_activities": "查询软件包活动并获取可引用数据对象",
            "query_asset_activities": "查询资产活动并获取可引用数据对象",
            "explore_entity": "沿已知实体身份和关系继续调查关联活动与上下文",
            "get_raw_records": "读取已授权活动对应的原始记录以核对关键字段",
            "calculate_activity_metrics": "对已授权活动执行确定性计算以验证行为模式",
        }[name]

    @classmethod
    def _finish(cls, state: InvestigationState, objective: str) -> FinishRequest:
        return FinishRequest(
            objective=objective,
            resolved_gap_ids=[item.gap_id for item in state.evidence_gaps if item.status == "resolved"],
            unresolved_gap_ids=[item.gap_id for item in state.evidence_gaps if item.status != "resolved"],
        )

    @classmethod
    def _convergence_guard(cls, state: InvestigationState) -> FinishRequest | None:
        calls = state.tool_calls
        reason = None
        if state.budget.iterations_used >= min(state.budget.max_iterations, 12):
            reason = "已达到在线调查轮次上限，使用现有查询结果生成研判报告"
        elif len(calls) >= 2 and all(item.status in {"denied", "error"} for item in calls[-2:]) \
                and calls[-1].tool_name == calls[-2].tool_name:
            reason = "同一数据工具连续失败，停止重复请求并在报告中说明限制"
        elif len(calls) >= 3 and len({item.tool_name for item in calls[-3:]}) == 1:
            reason = "连续调查动作没有增加新的数据能力，使用现有结果形成报告"
        return cls._finish(state, reason) if reason else None
