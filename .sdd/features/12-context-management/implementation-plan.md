# Context Management — Implementation Plan

每条步骤以"改动 + 验收"闭环。整体目标：上下文窗口提为模型资源配置项（初始 100K），工具结果回放改为 token 预算截断 + 摘要降级，每轮注入结构化进度投影；消除 feature 11 暴露的失忆循环。

## 步骤 1：上下文窗口配置项 + 轻量 token 估算器

**改动**：

- `shared/tokenizer.py`（新增）：`estimate_tokens(text)`，CJK 字符 0.6 / 其他 0.25，`max(1, int(...))`；附 `estimate_messages_tokens(messages)` 便于估算开销。
- `bootstrap/settings.py`：
  - `ModelSettings` 新增 `context_window_tokens: int = Field(default=100000, ge=1024, le=1000000)`；
  - `model(role)` 读取 `{PREFIX}_MODEL_CONTEXT_WINDOW_TOKENS`，兜底 `MODEL_CONTEXT_WINDOW_TOKENS`（默认 `100000`）；`report_model` 读取 `REPORT_MODEL_CONTEXT_WINDOW_TOKENS`。
- `.env` / `.env.example`：增加 `MODEL_CONTEXT_WINDOW_TOKENS=100000`。

**验收**：单测覆盖"默认 100K、按角色覆盖、env 读取"；`AppSettings.load()` 三模型窗口值正确。

## 步骤 2：可用预算推导 + 摘要降级

**改动**：

- `judgment/application/data_tool_planner.py`：
  - 新增 `_usable_context(state)`：`context_window - output_reserve(max_tokens) - system_overhead - 4096`；`system_overhead` 对 system prompt + 注册工具 schema 各估算一次。
  - 抽取/复用摘要降级：把 `tool_observation.py` 的 `_brief` 关键字段抽取逻辑提为可复用函数（或直接调用其静态方法），工具结果回放前先降级为关键字段摘要。
- 进度投影所需映射（定义在 planner 内，常量）：
  - 权限域 → activity_type：`process→{process}`、`network→{network,socket}`、`file→{file}`、`persistence→{service}`、`reputation→{package,asset}`。

**验收**：单测覆盖"预算 = 窗口 − 输出 − 开销 − 余量，且 >0"；大结果降级后不含 raw 大字段。

## 步骤 3：token 预算截断替换 `traces[-12:]` + 前缀一致性改造

**改动**：`data_tool_planner.py` 的 `_messages()`：

- **消息布局重构**：`[0] system_prompt`、`[1] case_context`（**移除 `budget`**，只剩 case_id/scope/entities/claims，字节级稳定）→ 工具历史（AIMessage + ToolMessage 成对）→ 尾部动态状态消息（budget + 进度 JSON + 轮次提醒）。
- 工具结果回放改为：先按**写入时定型**的摘要降级（见步骤 2），再按 `_usable_context` 预算**从新到旧**累加，超限即停；
- 以 **trace 为单位**（AIMessage + ToolMessage 成对）截断，保证不出现"有调用无结果"的协议违规；
- 稳定前缀（system + case_context）不被截断；
- 移除 `traces[-12:]`。

**验收**：单测覆盖"`[0]`/`[1]` 字节级稳定（不含动态字段）、回放 token 总量 ≤ 预算、工具调用/结果成对、从新到旧、稳定前缀不被截"。

## 步骤 4：结构化进度投影（尾部）

**改动**：`data_tool_planner.py` 的 `_messages()`：

- 每轮确定性算出进度 JSON（`round` / `queried_domains`（activity_type→{queries,returned}）/ `unqueried_domains`（授权映射后未查的 activity_type）/ `evidence_refs` / `authorized_scope`）；
- 从 `state.tool_calls`（已执行工具）统计 queried，从 `state.scope.allowed_domains` 经步骤 2 映射推导 unqueried；
- 进度 JSON 合并进**尾部动态状态消息**（与 budget、轮次提醒一起），不放入稳定前缀 `[1]`；
- **不注入任何"请结束调查"的硬性提示**。

**验收**：单测覆盖"已查 7 域后 unqueried 为空、部分查询时 unqueried 正确、进度 JSON 结构稳定、且位于尾部而非前缀"。

## 步骤 5：全量回归 + 真实 LLM 验证

**改动**：无新代码，验证收口。

**验收**：`pytest -q` 全绿；`c2-malicious-reference` 真实 LLM 调查：进度投影正确、模型查全后能收敛（不再 7~29 轮重复探查）、调查时长显著下降、结论质量不劣化。
