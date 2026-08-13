# Native Tool Calling — Implementation Plan

每条步骤以"改动 + 验收"闭环，末尾跑对应测试。整体目标：两条 planner 路径收敛到同一套 native function-calling 框架（面向 domain 的 9 个固定工具），`DeterministicPlanner` 与 18 个黄金 Case 行为不变。

## 步骤 1：抽取共享 native tool-calling 基础设施

**改动**：新建 `src/threat_agent/judgment/application/native_tool_calling.py`：

- 迁入并共享 `FinishInvestigationInput`、`RequestScopeExpansionInput` 两个动作工具 schema；
- `build_native_tools(specs)`：把 `(name, description, args_schema)` 包装为 `StructuredTool`（执行函数抛"执行归 graph 所有"）；
- `parse_tool_call(response)`：解析 `AIMessage.tool_calls[0]` → `(name, args, call_id)`；
- `serialize_messages()`：可观测性消息序列化。

**验收**：新增单测覆盖 `build_native_tools` / `parse_tool_call` / 动作 schema 可序列化；现有 `test_llm_investigation_tools.py` 保持绿（暂不改 `data_tool_planner`）。

## 步骤 2：ToolRegistry 注册 domain 固定工具 + gap 映射

**改动**：在 `judgment/adapters/tools.py` 增加 `ToolRegistry.native_tool_specs()` 与 domain 工具执行路径：

- 注册 5 个 domain 工具（`query_process_evidence` / `query_file_evidence` / `query_network_evidence` / `query_persistence_evidence` / `query_reputation_evidence`），schema 固定 = `gap_id`（str）+ 通用查询参数（`host_id` / `entity_ids` / `start_time` / `end_time` / `limit`）；
- 建立 `gap_id → (domain, required_evidence_types)` 映射，跨域 gap 归入 analyzer 路径（本步骤产出映射表并单测覆盖"每个查询类 gap 恰好归属一个 domain"）；
- 后端执行：`gap_id` → `required_evidence_types` ∩ domain → 查询，复用现有 `_query`。

**验收**：新增单测验证 5 个 domain 工具的 schema 固定、gap→domain 映射无遗漏/无重复归属；现有工具相关测试保持绿。

## 步骤 3：证据/分析路径接入 native 调用

**改动**：改造 `judgment/application/planner.py` 的 `StructuredJudgmentPlanner`：

- `plan()` 用 `native_tool_specs()` + `bind_tools` + `parse_tool_call` 构造 `EvidenceRequest` / `AnalysisRequest` / `ScopeRequest` / `FinishRequest`；
- 新增 `activate_scenario` 工具（schema `scenario` + `reason_refs`），模型提议 → `activate_scenario()` 确定性加载模板；`validate_action` 拒绝无效激活；
- 保留确定性前置（required analysis obligation 直接返回、无 eligible 直接 finish）；
- 保留 `DeepAgentsPlanner` 别名指向新实现。

**验收**：更新 `test_structured_planners.py` 与 `test_p1_investigation_loop.py` 的 planner 断言；新增单测覆盖 tool_call → action 映射、domain 工具选择、`activate_scenario` 工具化。

## 步骤 4：graph 循环回灌 ToolMessage + 文本注入可选值

**改动**：在 `judgment/application/graph.py` 的 `_plan_action` 中：

- 把历史 `state.tool_calls` + `state.evidence_packs` + `facts`/`findings` 摘要重放为 `AIMessage` + `ToolMessage` 对传给 planner；
- 每轮向 user 文本注入"当前可查的 gap 列表（含 domain 标注）+ 可用 evidence_refs"，供模型按 `gap_id`/`evidence_refs` 参数选值。

**验收**：单测验证多轮回灌消息结构与可选值注入；`test_judgment_graph.py`（确定性路径）保持绿。

## 步骤 5：数据路径收敛到统一框架

**改动**：`StructuredDataToolPlanner` 改用共享基础设施（动作 schema、`build_native_tools`、`parse_tool_call`、`serialize_messages`），4 个数据工具与 `InvestigationToolGateway` 执行语义不变。

**验收**：`test_llm_investigation_tools.py` 全绿；行为与改造前等价。

## 步骤 6：删除 interpretation + 清理兼容层 + 全量回归

**改动**：

- 删除 `interpretation` 字段及其消费点（`state_view`、`planner.py` 的 interpretation 分支、`read_model`、`case_projector`、展示契约、`validate_verdict` 中的 interpretation 校验）；
- 核对 `DeepAgentsPlanner` 别名、`InvestigationEngine` 兼容面、`cli.py` / `demo.py` 接线；清理重复动作 schema。

**验收**：全量 `pytest -q` 绿（150 项测试 + 18 个 Case）；删除 `interpretation` 后无残留引用；如模型可用，跑一次 `--mode llm` 冒烟验证真实 function calling 与多轮回灌。
