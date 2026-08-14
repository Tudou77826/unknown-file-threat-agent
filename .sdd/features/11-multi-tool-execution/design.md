# Multi-Tool Execution — Design

## 1. 现状（问题根因，已实测确认）

调查执行循环（`JudgmentGraph`）每轮只执行模型规划的第一个工具，其余被静默丢弃：

- `native_tool_calling.py` 的 `parse_tool_call` 只取 `response.tool_calls[0]`；
- 模型（DeepSeek）在 `parallel_tool_calls=False` 下**仍然一次返回多个工具调用**（该参数未生效）；
- 实测：模型每轮都规划了 `query_file_activities`、`query_network_activities`，但代码只执行了第一个 `query_process_activities`，其余全丢。

次生问题：`_convergence_guard` 看到"连续 3 次同一工具"，误判为"无信息增益"，提前结束调查。两者叠加导致：数据里明明有 network/file/service 等强证据，却只查了 process 域，结论被拉低。

## 2. 目标

1. 模型每轮规划的多个工具调用**全部按序执行**，不再丢弃。
2. 兜底校验：没有执行条件的工具调用拒绝执行，给简短拒绝理由；不影响其他工具。
3. 失败的调用正常返回失败信息，模型下一轮自行处理。
4. 预算只按"轮次"控制；超过阈值后每轮对话末尾追加轮次提醒。
5. 移除 `parallel_tool_calls=False`（无效且非预期）。

## 3. 做法

### 3.1 解析多工具
`parse_tool_call` → `parse_tool_calls`，返回 `list[(name, args, call_id)]`。

### 3.2 规划器返回动作列表
`StructuredDataToolPlanner.plan()` 返回 `list[InvestigationAction]`：每个 tool_call 转成一个动作；移除 `_convergence_guard` 及其调用。

### 3.3 执行循环批量化
`JudgmentGraph` 用 pending 队列逐个执行本轮动作：执行完一个，队列还有剩余则继续校验/执行下一个；队列清空才进入下一轮（`iterations_used + 1`）。即"一轮 = 一次模型规划 + 该轮所有工具按序执行"。

### 3.4 兜底校验 + 拒绝
逐个动作走 `validate_action`（移除其中的 tool-call 预算检查）。校验失败 → 拒绝该动作，记录简短拒绝理由到 `InvestigationToolTrace`（作为 ToolMessage error 回放），继续处理下一个，不触发整体 repair。

### 3.5 轮次预算 + 提醒
- 轮次上限 30（`max_iterations = 30`）。
- `iterations_used > 15` 时，每轮 `_messages()` 末尾追加一条 system 消息：`{system_remind}可用会话轮次：{iterations_used}/{max_iterations} {/system_remind}`。

## 4. 已确认决策

1. **并发兜底**：不主动阻止并发，但做必要校验；没有执行条件的 toolcall 拒绝执行并给简短理由。
2. **失败处理**：失败的 toolcall 正常返回失败信息，模型自己处理。
3. **预算口径**：只显示轮次（`iterations`），tool-call 计数仅作统计、不再作拒绝依据。
4. **移除收敛守卫**：用轮次预算 + 超过 15 轮后每轮末尾追加轮次提醒取代。
5. **移除 `parallel_tool_calls=False`**：该参数无效且非预期。

## 5. 代价与边界（已向用户说明）

- 核心执行循环 `graph.py` 改动需谨慎，是本 Feature 主要风险点。
- 收敛守卫移除后，调查收敛完全依赖轮次上限 + 模型自身的 `finish_investigation` 判断；不再有"连续同工具=无增益"的强制刹车。
- 测试中 `test_data_tool_planner_stops_repeated_tool_loop_before_model_call` 断言"重复工具即 Finish"，需随收敛守卫移除而改写。

## 6. 遗留发现（本 Feature 暴露，待单独立项）

### 6.1 上下文管理缺失（根因级欠账）

实测（`c2-malicious-reference`）发现：模型在前 6 轮查全 7 个域后，第 7～29 轮持续重复探查，直到 30 轮耗尽。根因不是模型能力，而是**上下文管理缺失**：

- 规划器唯一"上下文管理"是 `data_tool_planner.py` 的 `for trace in state.tool_ledger.traces[-12:]`：把最近 12 条工具结果**原封不动**回放，既无压缩、无摘要、无进度投影、无 token 预算，也不按字节/语义截断（只按条数）。
- 实测单轮 tool 结果可达 4.5 万～9.6 万字符，第一轮 input 即 5012 tokens。
- 7 个域查全后，第 13 条工具结果把最早的 `query_process_activities` 挤出窗口，模型"忘记自己查过该域"而回头重查，形成失忆式循环。

`state.tool_ledger.query_results` / `authorized_activity_refs` 里其实保存了完整进度，但从未投影给模型。**结论：上下文管理（压缩/摘要/进度投影/分层记忆）一行都未实现，属独立架构欠账，需单独立项。**

