# Native Tool Calling Design

## 结论

研判引擎存在两条 LLM 规划路径，范式不一致：证据/分析路径（`StructuredJudgmentPlanner`，CLI 主路径）是**伪 agentic**——模型只返回一个 `tool_name` 字符串，参数由确定性代码补齐；数据路径（`StructuredDataToolPlanner`，demo 路径）已是**正规 function calling**。

本 Feature 将两条路径收敛到统一的原生 function-calling 框架：模型直接产出工具调用与参数。证据/分析路径的工具从 40+ 个 evidence_type 细粒度工具**收敛为 9 个固定工具**（5 个 domain 查询 + 分析 + 场景切换 + 扩范围 + 结束），面向 domain、参数自由表达；内部引用参数（`gap_id` / `evidence_refs`）采用**固定 schema + 文本注入可选值 + `validate_action` 兜底**。旧的 `interpretation` 自由文本通道删除。确定性护栏与 18 个黄金 Case 基线不变。

## 现状

两条路径走同一个 `JudgmentGraph`（plan → validate → execute）循环，仅"如何调用工具"不同：

| 路径 | 实现 | 范式 | 接入点 |
|---|---|---|---|
| 证据/分析 | `StructuredJudgmentPlanner`（`planner.py`） | `json_mode` 返回 `tool_name` 字符串 | `cli.py` `mode="llm"` |
| 数据 | `StructuredDataToolPlanner`（`data_tool_planner.py`） | `bind_tools` + `tool_calls` + `ToolMessage` | `demo.py` `mode="llm"` |

### 伪 agentic 的病灶（证据/分析路径）

`StructuredJudgmentPlanner.plan()` 的调用链：

1. `ToolRegistry.catalog(state)` 确定性算出 eligible 工具及每个工具的 `compatible_gap_ids` / `eligible_evidence_refs`；
2. 模型只返回 `PlannerSelection`（一个 `tool_name` 字符串）；
3. `_build_action()` 从 catalog 取 `compatible_gap_ids[0]`、全量 `eligible_evidence_refs`，确定性构造请求。

由此：模型不构造查询参数（`host_id` / `entity_ids` / `filters` / `limit` 全默认）；`gap_id` 与 `evidence_refs` 被代码写死；`planner.py:426` 的兼容别名 `DeepAgentsPlanner = StructuredJudgmentPlanner` 注释自陈 "no longer uses Deep Agents"。

### 正规化的参照实现

`StructuredDataToolPlanner` 已是目标范式：`StructuredTool.from_function` + `args_schema` 定义工具，`bind_tools(tool_choice="required", strict=True, parallel_tool_calls=False)`，`_messages()` 把 `tool_ledger.traces` 重放为 `AIMessage` + `ToolMessage` 多轮记忆。本 Feature 以它为模板。

### 必须保留的护栏

- `catalog(state)` 资格约束（分析工具证据前置、domain 在 scope、gap 未关闭）；
- `validate_action()` 策略兜底（host/entity/time/limit 越界、重复 analysis、finish 关门门槛）；
- 确定性 `Analyzer`（LLM 不直接产 Fact/Finding）与 `verdict.py` 门槛。

## 工具设计（面向 domain）

### 设计原则

LLM function calling 用不好的根因不是模型，而是工具设计：

1. 工具太多 → 选择困难、易选错；
2. 工具名/参数名是内部 ID（`file_content_change`）→ 需额外推理语义；
3. 参数合法值不明确 → 不知道能填什么。

因此：**工具按 domain 收敛为语义清晰的小集合；LLM 面对"调查问题"（`gap_id` 背后的自然语言 question），不面对内部 `evidence_type`；查询参数（host/time/limit）是 LLM 该自由发挥的部分，予以保留。**

### 工具清单（9 个固定）

| # | 工具 | 职责 | 关键参数 |
|---|---|---|---|
| 1 | `query_process_evidence` | 查进程域证据 | `gap_id` + 通用查询参数 |
| 2 | `query_file_evidence` | 查文件域证据 | 同上 |
| 3 | `query_network_evidence` | 查网络域证据 | 同上 |
| 4 | `query_persistence_evidence` | 查持久化域证据 | 同上 |
| 5 | `query_reputation_evidence` | 查信誉/基线证据 | 同上 |
| 6 | `analyze_evidence` | 触发确定性分析（evidence → fact/finding） | `evidence_refs` |
| 7 | `activate_scenario` | 依据已存在证据动态激活场景模板 | `scenario` + `reason_refs` |
| 8 | `request_scope_expansion` | 跨主机范围审批 | 复用现有 schema |
| 9 | `finish_investigation` | 结束调查 | 复用现有 schema |

通用查询参数：`host_id` / `entity_ids` / `start_time` / `end_time` / `limit`。

### gap → domain 映射

- `gap_id` 是 `str`，不 enum；当前可选的 gap 及其 domain 由每轮 user 文本注入（`state_view` 已具备此能力，补 domain 标注即可）。
- 后端由 `gap_id` → `gap.required_evidence_types` ∩ 该 domain → 查询，LLM 不接触 `evidence_type`。
- 跨域 gap（如 `gap-exfiltration-chain`）由 `analyze_evidence` 通过 analyzer 解决，不通过单次 domain 查询。
- LLM 选错 domain 或 gap 时，`validate_action` 拒绝并走 repair 收敛。

### LLM 每轮动作示例

> 看到 `gap-network`（network 域）未解决 → `query_network_evidence(gap_id="gap-network")` → 证据回来 → `analyze_evidence(evidence_refs=[...])` → 发现可疑 → `query_persistence_evidence(gap_id="gap-persistence")` → …… → `finish_investigation(...)`

### 缓存友好机制

**稳定信息放工具 schema（prompt 前缀），动态信息放 user 文本（prompt 尾部）。**

- 9 个工具名 + 参数名固定 → `tools` 字段恒定 → 跨轮前缀缓存可复用；
- "当前可查哪些 gap、哪些 evidence_ref 可用、状态如何"写进 user 消息，只动尾部，不动前缀；
- `gap_id` / `evidence_refs` 用 `str`（非动态 enum），靠文本注入 + `validate_action` 兜底。

> 说明：此前草案提的"动态 enum"会导致 `tools` 字段每轮变化，破坏跨轮前缀缓存（vLLM prefix caching / SGLang RadixAttention），现已废弃。`bind_tools` 每轮重建对象本身不影响服务端缓存，影响缓存的是请求体 `tools` 字段内容是否变化。

### 记忆原则：上下文是工作记忆，state 是长期记忆

不靠模型对话上下文承载跨轮信息——每一轮模型输入都从 `state` 重新序列化。这条原则对应两个落点：

- **动态流程**做成工具（受控状态转移）：`activate_scenario` 加载已审核的本地模板，确定性新增 hypothesis/role/gap。
- **思路过程**拆成结构化状态字段，不新增游离自由文本：短期推理落 `planner_decisions[].decision_summary`；结论表达落 `findings` / 报告层 `executive_summary`。旧 `interpretation` 字段当前不参与 verdict、不进报告，仅展示计数，本期删除。

## 收敛边界

| | 内容 |
|---|---|
| 收敛 | "LLM 如何调用工具"：8 个固定工具、`bind_tools`、`tool_call` 解析、`ToolMessage` 回灌、动作工具 schema |
| 不收敛 | 判恶与报告语义（确定性 `verdict.py` vs LLM 报告）、工具执行语义（`ToolRegistry.invoke` vs `InvestigationToolGateway.invoke`）、gap/analyzer/verdict 领域规则 |

即统一的是 planner 层，不触及调查引擎判恶语义——与"方向 = 仓库当前穿刺结论"一致。

## 做法

机制要点（分步见 [implementation-plan.md](implementation-plan.md)）：

1. **共享基础设施**：新建 `judgment/application/native_tool_calling.py`，承载动作 schema、`build_native_tools`、`parse_tool_call`、`serialize_messages`，供两条路径共用。
2. **domain 工具注册**：在 `ToolRegistry` 增加 `native_tool_specs()`，生成 5 个 domain 工具的固定 schema（`gap_id` + 通用查询参数）+ 后端 gap→evidence_types 映射。
3. **接入 native 调用**：`StructuredJudgmentPlanner.plan()` 每轮 `bind_tools` 后解析 `tool_calls[0]` 构造 `EvidenceRequest` / `AnalysisRequest` / `ScopeRequest` / `FinishRequest`，并处理 `activate_scenario`（模型提议 → `activate_scenario()` 确定性加载模板）。保留确定性前置。
4. **回灌工具结果**：`JudgmentGraph._plan_action` 把历史调用与结果重放为 `AIMessage` + `ToolMessage` 传给 planner（证据路径回灌 `tool_calls` / `evidence_packs`；数据路径回灌 `tool_ledger.traces`）。
5. **数据路径收敛**：`StructuredDataToolPlanner` 改用共享基础设施，4 个数据工具与 `InvestigationToolGateway` 执行语义不变。

## 关键决策

- **范围**：两条路径收敛统一（仅 planner 层）。
- **工具粒度**：面向 domain 的 9 个固定工具（5 domain + analyze + activate_scenario + scope + finish）。
- **参数约束**：固定 schema + 文本注入可选值 + `validate_action` 兜底（废弃动态 enum）。
- **旧能力去留**：`activate_scenario` 保留为工具；`interpretation` 本期删除（思路落 `planner_decisions` / `findings` / 报告层）。

## 风险

- 5 个 domain 工具的 gap→domain 映射需覆盖全部 gap，跨域 gap 需归入 analyzer 路径，映射遗漏会导致 LLM 无法查询某些 gap；
- 删除 `interpretation` 会改动 `state_view` / `read_model` / `case_projector` / 展示契约及 5 个语义测试，需同步清理；
- 需真实模型验证 OpenAI-compatible 对 `strict=True` + 固定工具集的兼容性；
- 影响 planner 相关单测（`test_structured_planners.py` / `test_p1_investigation_loop.py` / `test_llm_investigation_tools.py`）。

## 验收标准

- 证据/分析路径与数据路径均经 `bind_tools` 产出原生 `tool_calls`，模型可直接指定查询参数；
- 9 个固定工具 schema 稳定，跨轮 `tools` 字段不变；
- `gap_id` / `evidence_refs` 通过文本注入 + 兜底约束，模型无法选中 ineligible 值；
- `activate_scenario` 经工具调用后确定性加载场景模板，`validate_action` 拒绝无效激活；
- `interpretation` 字段及其展示/序列化清理完毕；
- 18 个黄金 Case `DeterministicPlanner` 回归全绿；
- 两条路径 LLM 冒烟（含多轮 `ToolMessage` 回灌）通过；
- `validate_action` 兜底语义不变。
