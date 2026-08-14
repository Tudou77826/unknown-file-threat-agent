# Multi-Tool Execution — Implementation Plan

每条步骤以"改动 + 验收"闭环。整体目标：让模型每轮规划的多个工具调用全部按序执行，移除失效的 `parallel_tool_calls=False` 与收敛守卫，改用轮次预算 + 轮次提醒。

## 步骤 1：解析多工具调用

**改动**：`judgment/application/native_tool_calling.py`

- `parse_tool_call(response)` → `parse_tool_calls(response)`，返回 `list[tuple[str, dict, str]]`；
- 保留空列表/非法条目兜底。

**验收**：单测覆盖"多 tool_call 全部解析、空返回空列表"。

## 步骤 2：规划器返回动作列表 + 移除收敛守卫/parallel + 轮次提醒

**改动**：`judgment/application/data_tool_planner.py`

- `bind_tools(...)` 移除 `parallel_tool_calls=False`；
- `plan()` 返回 `list[InvestigationAction]`（每个 tool_call 转一个动作；无 tool_call 时返回 `[FinishRequest]`）；
- 移除 `_convergence_guard` 及其调用；
- `_messages()`：`state.budget.iterations_used > 15` 时追加 `{system_remind}可用会话轮次：{iterations_used}/{max_iterations} {/system_remind}` 的 system 消息。

**验收**：单测覆盖"多 tool_call 全部转动作、无 tool_call 转 Finish、移除收敛守卫后不再因重复工具强制 Finish"。

## 步骤 3：执行循环批量化 + 预算口径

**改动**：

- `judgment/application/policy.py`：`validate_action` 移除 tool-call 预算检查（`tool_calls_used >= max_tool_calls` 不再拒绝）。
- `judgment/application/graph.py`：`JudgmentGraphState` 增加 `pending_actions`；`_plan_action` 接列表并设第一个为当前 action、其余入队；`_execute_action` 执行完一个后若队列非空则弹下一个并回到校验，队列空才 `route="continue"`；校验失败走"拒绝 + 理由"（记录 trace）而非整体 repair。

**验收**：单测覆盖"一轮多工具按序执行、队列清空才进下一轮、tool-call 预算不再拒绝"。

## 步骤 4：观测层适配

**改动**：`bootstrap/demo.py` 的 `ObservableJudgmentPlanner`

- `plan()` 返回列表后，emit 决策事件改为逐条（每工具一条 decision，或合并为一条多工具 decision），保持节点归属 `plan`。

**验收**：demo 事件流里本轮规划的所有工具调用都可见。

## 步骤 5：测试更新 + 全量回归 + 真实 LLM 验证

**改动**：`tests/test_llm_investigation_tools.py` 等

- 更新 `plan()` 返回列表相关断言；
- 改写 `test_data_tool_planner_stops_repeated_tool_loop_before_model_call`（收敛守卫已移除）；
- 补充 `parse_tool_calls`、批量执行、轮次提醒的用例。

**验收**：`pytest -q` 全绿；对 `c2-malicious-reference` 跑真实 LLM，核对：本轮规划的 process/file/network 等工具全部执行、报告查询边界覆盖多域、结论不再被过早收敛拉低。
