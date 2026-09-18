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
from ...shared.llm import invoke_llm
from ...shared.tokenizer import estimate_messages_tokens
from ..domain.models import (
    DataToolRequest,
    FinishRequest,
    InvestigationAction,
    InvestigationState,
)
from .native_tool_calling import (
    FinishInvestigationInput,
    build_native_tools,
    parse_tool_calls,
    serialize_messages,
)


class DataToolSelection(StrictModel):
    """Legacy contract retained for stored events; online planning uses native tool calls."""

    action: Literal[
        "query_process_activities", "query_network_activities", "query_socket_activities",
        "query_file_activities", "query_service_activities", "query_package_activities",
        "query_asset_activities", "explore_entity", "get_raw_records",
        "calculate_activity_metrics", "finish_investigation",
    ]
    objective: str = Field(default="执行下一步受控数据调查", min_length=10)
    arguments: dict[str, Any] = Field(default_factory=dict)


# After this many iterations, append a session-round reminder to the model.
REMINDER_THRESHOLD = 15

# Context compaction triggers once total estimated input reaches this fraction
# of the model's context window.
COMPACTION_TRIGGER_PCT = 0.70

# Keep this many most-recent tool traces as raw text after compaction; older
# traces are folded into the LLM-written progress summary.
KEEP_RECENT_TRACES = 6

# Tool name -> activity_type for progress projection and budget accounting.
_TOOL_TO_ACTIVITY_TYPE = {
    "query_process_activities": "process",
    "query_network_activities": "network",
    "query_socket_activities": "socket",
    "query_file_activities": "file",
    "query_service_activities": "service",
    "query_package_activities": "package",
    "query_asset_activities": "asset",
}

# Authorized permission domain -> the concrete activity_types it covers. Used
# to derive "unqueried" domains in the progress projection.
_DOMAIN_TO_ACTIVITY_TYPES = {
    "process": ["process"],
    "network": ["network", "socket"],
    "file": ["file"],
    "persistence": ["service"],
    "reputation": ["package", "asset"],
}

_COMPACTION_SYSTEM_PROMPT = (
    "你是安全调查的上下文压缩器。把一段旧的调查历史压缩成结构化的调查进展摘要，"
    "尽可能保留有价值的信息：查了哪些数据领域及关键发现、发现的关键证据（谁、对什么、"
    "做了什么，保留 evidence_id/activity_id）、已确认或候选的实体关系、以及尚未查证或待确认的缺口。"
    "必须继承上一版摘要中已经记录的内容，再并入新增工具历史里的信息，不得从头重写而丢失旧信息。"
    "只输出结构化的中文摘要，不要输出无关内容。"
)


# Model-facing tool catalog: (name, args_schema, description). Shared by the
# non-executing planner catalog and by executing gateway bindings.
TOOL_DEFINITIONS = [
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
    ("finish_investigation", FinishInvestigationInput,
     "现有证据足以形成结论、继续查询没有信息增益或预算将耗尽时，结束调查并生成报告。"),
]


def investigation_tools() -> list:
    """Return the exact schemas registered with the chat model.

    Query tools are split by activity domain: each tool's name fixes the
    domain, and its schema exposes only that domain's fields.
    """
    return build_native_tools(TOOL_DEFINITIONS)


# Shared investigation planner system prompt.  The formal create_agent-based
# middleware runtime is its production consumer; the native planner only
# remains for low-level migration and regression coverage.
PLANNER_SYSTEM_PROMPT = (
    "你是未知文件安全调查的取证规划器。根据案件证据和历次工具返回，规划下一步调查动作，"
    "可以一次规划多个工具调用（按顺序执行）。"
    "工具参数必须严格遵循已注册 JSON Schema，不要自行创造字段。"
    "不需要的过滤字段直接省略，不要填写 \"null\"、\"none\" 或空字符串。"
    "租户、案件、run_id 和授权 Scope 由系统注入，不得作为工具参数提交。"
    "调查边界固定为唯一告警主机的本机数据：没有跨主机查询工具，"
    "发现涉及其他主机的线索时不要尝试查询目标主机，继续完成本机取证，"
    "跨主机线索留给最终报告作为未解决问题或限制记录。"
    "空结果只代表该次查询在执行边界内返回零条，不能据此断言行为没有发生。"
    "候选关系只能用于继续调查，不能当作已确认事实。"
    "host_refs 必须使用 authorized_scope.host_ids 中的原始值，例如 server-01，不要添加 host: 前缀。"
    "explore_entity 只接受先前数据工具结果中出现的平台 entity_id，不要直接使用案件实体 ID。"
    "get_raw_records 和 calculate_activity_metrics 的参数只能引用本次运行中活动查询返回的活动 ID；"
    "案件上下文里的实体 ID（例如上游上报的进程链）属于线索而非证据，直接引用会被边界拒绝——"
    "需要查看某个进程的原始记录或统计时，先用 query_process_activities 等查询取得活动 ID 再引用它们。"
    "必须逐字复制工具返回中的 evidence_ids，禁止按命名规律自行构造或推测 ID；"
    "被拒绝时阅读拒绝原因并更换查询方式，不要重复同一次调用。"
    "当进一步查询没有信息增益时调用 finish_investigation。"
)


class StructuredDataToolPlanner:
    """Native OpenAI-compatible tool-calling planner controlled by JudgmentGraph."""

    uses_data_tools = True

    def __init__(
        self,
        model: Any,
        event_sink: Callable | None = None,
        *,
        context_window_tokens: int = 100000,
        output_reserve_tokens: int = 4096,
    ):
        self.tools = investigation_tools()
        self.model = model
        self.bound_model = model.bind_tools(
            self.tools,
            tool_choice="required",
            strict=True,
            extra_body={"thinking": {"type": "disabled"}},
        )
        self.event_sink = event_sink or (lambda _kind, _message, _details=None: None)
        self.context_window_tokens = context_window_tokens
        self.output_reserve_tokens = output_reserve_tokens
        # Compaction state, persisted on the planner instance across rounds
        # within a single investigation run.
        self._compaction_summary = ""
        self._replay_from = 0
        self.system_prompt = PLANNER_SYSTEM_PROMPT

    def plan(self, state: InvestigationState) -> list[InvestigationAction]:
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
        response = invoke_llm(
            lambda: self.bound_model.invoke(messages),
            on_failure=lambda _attempt, error, _kind: self.event_sink(
                "model_output", "研判模型调用失败", {
                    "phase": "judgment_planning",
                    "iteration": state.budget.iterations_used,
                    "error_type": type(error).__name__,
                    "error_message": str(error),
                }
            ),
        )
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
            return [self._finish(state, "模型未请求新的数据工具，使用现有调查结果生成研判报告")]

        data_tool_names = {
            "query_process_activities", "query_network_activities", "query_socket_activities",
            "query_file_activities", "query_service_activities", "query_package_activities",
            "query_asset_activities", "explore_entity", "get_raw_records", "calculate_activity_metrics",
        }
        actions: list[InvestigationAction] = []
        for index, (name, arguments, call_id) in enumerate(parse_tool_calls(response)):
            if not call_id:
                call_id = f"tool-call-{state.budget.iterations_used}-{index}"
            if name in data_tool_names:
                actions.append(DataToolRequest(
                    tool_name=name,
                    objective=self._objective(name),
                    arguments=arguments,
                    tool_call_id=call_id,
                    model_message={
                        "content": response.content,
                        "tool_call": {"name": name, "args": arguments, "id": call_id, "type": "tool_call"},
                        "additional_kwargs": response.additional_kwargs,
                        "response_metadata": response.response_metadata,
                        "usage_metadata": response.usage_metadata,
                    },
                ))
            elif name == "finish_investigation":
                actions.append(FinishRequest(**arguments))
            else:
                raise ValueError(f"Model requested an unregistered tool: {name}")
        return self._order_actions(actions)

    @staticmethod
    def _order_actions(actions: list[InvestigationAction]) -> list[InvestigationAction]:
        # finish_investigation must run last: if the model mixed it with other
        # calls, move it to the end so remaining queries still execute first.
        finish = [item for item in actions if isinstance(item, FinishRequest)]
        others = [item for item in actions if not isinstance(item, FinishRequest)]
        return others + finish

    def _messages(self, state: InvestigationState) -> list[Any]:
        # Message layout (prefix-cache friendly):
        #   [0] system_prompt                 — byte-stable; the ONLY system message,
        #                                          since qwen/DashScope rejects any
        #                                          additional system role mid-conversation
        #   [1] case_context (no budget)      — byte-stable
        #   [2] progress summary (optional)   — written once, replaced only on compaction
        #   [3..] raw tool call pairs         — most-recent traces, kept verbatim
        #   [last] dynamic state message      — changes each round, recomputed only
        # Mid-conversation injections (summary, dynamic state) are delivered as
        # tagged HumanMessages: providers such as qwen/DashScope allow exactly one
        # system message and it must come first.
        prefix = [
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=json.dumps(self._case_context(state), ensure_ascii=False)),
        ]
        dynamic = self._build_dynamic_state(state)
        self._maybe_compact(state, prefix, dynamic)
        tool_history = self._build_tool_history(state)
        return prefix + tool_history + dynamic

    def _case_context(self, state: InvestigationState) -> dict[str, Any]:
        """Byte-stable case context: no budget/round/progress fields."""
        return {
            "case_id": state.case_id,
            "authorized_scope": state.scope.model_dump(mode="json"),
            "entities": [item.model_dump(mode="json") for item in state.entities],
            "claims": [item.model_dump(mode="json") for item in state.claims],
        }

    def _compaction_threshold_tokens(self) -> int:
        return int(COMPACTION_TRIGGER_PCT * self.context_window_tokens)

    def _maybe_compact(
        self,
        state: InvestigationState,
        prefix: list[Any],
        dynamic: list[Any],
    ) -> None:
        """Compress old tool history once total input crosses the trigger.

        Raw history is replayed verbatim below the threshold; only when the
        whole message list reaches 70% of the window do we fold the oldest
        traces into an LLM-written summary.
        """
        traces = state.tool_ledger.traces
        # Nothing to fold if the un-summarized span is already small enough.
        if len(traces) - self._replay_from <= KEEP_RECENT_TRACES:
            return
        current = prefix + self._build_tool_history(state) + dynamic
        if estimate_messages_tokens(current) < self._compaction_threshold_tokens():
            return
        self._compact(state)

    def _compact(self, state: InvestigationState) -> None:
        traces = state.tool_ledger.traces
        keep_from = max(self._replay_from, len(traces) - KEEP_RECENT_TRACES)
        if keep_from <= self._replay_from:
            return
        to_compact = traces[self._replay_from:keep_from]
        summary = self._generate_summary(self._compaction_summary, to_compact)
        if summary:
            self._compaction_summary = summary
            self._replay_from = keep_from

    def _generate_summary(self, previous: str, traces: list) -> str | None:
        items = [
            {
                "tool": trace.tool_name,
                "arguments": trace.arguments,
                "result": trace.result,
            }
            for trace in traces
        ]
        payload = json.dumps(
            {"previous_summary": previous or None, "new_tool_history": items},
            ensure_ascii=False,
        )
        messages = [
            {"role": "system", "content": _COMPACTION_SYSTEM_PROMPT},
            {"role": "user", "content": payload},
        ]

        def invoke_once() -> str:
            response = self.model.invoke(messages)
            content = getattr(response, "content", "")
            if isinstance(content, list):
                content = "".join(str(part) for part in content)
            return str(content or "").strip()

        try:
            text = invoke_llm(
                invoke_once,
                parse_max_attempts=1,
                transport_max_attempts=2,
                transport_backoff=1.0,
            )
        except Exception:
            # Compaction is best-effort: on failure keep history verbatim and
            # retry on a later round. Never drop information silently.
            return None
        return text or None

    def _build_tool_history(self, state: InvestigationState) -> list[Any]:
        """Replay tool history: summary first, then recent raw traces verbatim."""
        messages: list[Any] = []
        if self._compaction_summary:
            messages.append(HumanMessage(
                content=f"<investigation_history_summary>\n{self._compaction_summary}\n</investigation_history_summary>"
            ))
        for trace in state.tool_ledger.traces[self._replay_from:]:
            call_id = trace.tool_call_id or f"trace-{trace.sequence}"
            ai = AIMessage(
                content=trace.model_message.get("content", ""),
                tool_calls=[{
                    "name": trace.tool_name,
                    "args": trace.arguments,
                    "id": call_id,
                    "type": "tool_call",
                }],
                additional_kwargs=dict(trace.model_message.get("additional_kwargs") or {}),
                response_metadata=dict(trace.model_message.get("response_metadata") or {}),
            )
            tool = ToolMessage(
                content=json.dumps(trace.result, ensure_ascii=False),
                tool_call_id=call_id,
                name=trace.tool_name,
                status="error" if trace.result_type == "ToolError" else "success",
            )
            messages.append(ai)
            messages.append(tool)
        return messages

    def _build_dynamic_state(self, state: InvestigationState) -> list[Any]:
        """Assemble the trailing per-round state message (budget + progress + reminder)."""
        progress = self._build_progress(state)
        parts: list[str] = [json.dumps(progress, ensure_ascii=False)]
        if state.budget.iterations_used > REMINDER_THRESHOLD:
            parts.append(
                f"{{system_remind}}可用会话轮次：{state.budget.iterations_used}/{state.budget.max_iterations} {{/system_remind}}"
            )
        return [HumanMessage(content="\n".join(parts))]

    def _build_progress(self, state: InvestigationState) -> dict[str, Any]:
        """Deterministic progress projection derived from the tool ledger."""
        queried: dict[str, dict[str, int]] = {}
        explored: dict[str, dict[str, int]] = {}
        for trace in state.tool_ledger.traces:
            activity_type = _TOOL_TO_ACTIVITY_TYPE.get(trace.tool_name)
            if activity_type is not None:
                bucket = queried.setdefault(activity_type, {"queries": 0, "returned": 0})
                bucket["queries"] += 1
                bucket["returned"] += self._trace_returned_count(trace.result)
            elif trace.tool_name == "explore_entity":
                ref = (trace.arguments or {}).get("entity_ref")
                if ref:
                    bucket = explored.setdefault(ref, {"resolved": 0, "candidate": 0})
                    result = trace.result
                    if isinstance(result, dict):
                        bucket["resolved"] += len(result.get("resolved_relations") or [])
                        bucket["candidate"] += len(result.get("candidate_relations") or [])

        all_authorized: list[str] = []
        for domain in state.scope.allowed_domains:
            all_authorized.extend(_DOMAIN_TO_ACTIVITY_TYPES.get(domain, [domain]))
        unqueried = sorted(set(all_authorized) - set(queried))

        return {
            "round": state.budget.iterations_used,
            "queried_domains": queried,
            "unqueried_domains": unqueried,
            "explored_entities": explored,
            "evidence_refs": len(state.tool_ledger.authorized_activity_refs),
            "authorized_scope": {
                "host_ids": state.scope.host_ids,
                "allowed_domains": state.scope.allowed_domains,
            },
        }

    @staticmethod
    def _trace_returned_count(result: dict[str, Any]) -> int:
        if not isinstance(result, dict):
            return 0
        boundary = result.get("execution_boundary") or {}
        if isinstance(boundary, dict) and "returned_count" in boundary:
            return int(boundary["returned_count"] or 0)
        if "returned_count" in result:
            return int(result["returned_count"] or 0)
        activities = result.get("activities") or result.get("timeline") or []
        return len(activities) if isinstance(activities, list) else 0

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
        return FinishRequest(objective=objective)
