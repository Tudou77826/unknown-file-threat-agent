# Agent Middleware Foundation — Design

## 1. 背景与现状

三项横切能力已在自建 LangGraph 图中实现并经 112 项测试覆盖，但实现形态绑定在研判图节点和领域状态模型上，其他 Agent 无法复用：

| 能力 | 现有实现 | 位置 |
|---|---|---|
| 边界防护 | `InvestigationBoundaryPort`：调用前授权 + 结果入账前校验 + 结构化拒绝 | `judgment/application/boundary.py` 定义，`case_management/application/boundary_policy.py` 实现 |
| 预算熔断 | `Budget` 三维计数（迭代 / 工具调用 / 报告重判）+ 图节点内检查，超额降级不崩溃 | `judgment/domain/models.py`、`judgment/application/graph.py` |
| 上下文压缩 | 水位触发 compaction + `brief_result` 确定性字段投影 | `judgment/application/data_tool_planner.py`、`tool_observation.py` |

外部事实（2026-08 核查）：

1. LangChain 1.x 已把 middleware 定为 `create_agent` 的核心扩展机制：`AgentMiddleware` 提供 `wrap_model_call` / `wrap_tool_call` / `wrap_agent_call` / `modify_model_request` 等 wrap 钩子，middleware 可通过 `state_schema` 扩展 agent 状态；官方内置 `SummarizationMiddleware`。对 LangGraph 增强的标准形态是 middleware，不是自建图。
2. 能力型工具防护（调前授权 + 结果校验）在开源框架中是空白：DeepMind CaMeL 只有研究级实现，主流框架的 guardrails 停留在输入输出内容过滤。
3. run 级动态预算熔断稀缺：多数框架只有 max_turns / recursion_limit 统计型限制，不限制。
4. 上下文压缩机制（水位触发 + 摘要 + 保留近期）已是主流标配（官方 SummarizationMiddleware、Claude Code、Anthropic compaction API），自研整条压缩链没有差异化价值；差异在领域感知的降采样策略。
5. 官方已内置 `ModelCallLimitMiddleware` / `ToolCallLimitMiddleware`（调用计数限制，含 exit_behavior），但无 token 维度、无业务可注入的降级契约。BudgetMiddleware 的增量定位收窄为：token 维度、多预算协同策略、降级出口与预算事件。
6. langchain 1.2 的钩子面为 `before_agent` / `after_agent` / `before_model` / `after_model` / `wrap_model_call` / `wrap_tool_call`（无 `wrap_agent_call`）；为此项目依赖从 langgraph 1.0 升级到 1.1+（1.x 承诺 2.0 前无破坏性变更，升级后存量测试全部通过）。

## 2. 目标

1. 交付不依赖业务模型的 middleware 组件包，三项能力可独立挂载、独立测试。
2. 正式在线调查采用 create_agent + middleware；CaseGraph 只保留案件生命周期、审批与处置编排职责。
3. 策略接口与实现分离：组件包只定义领域无关协议，单主机边界、案件预算等业务语义留在业务侧实现。

## 非目标

- 不替换 LLM 分级重试：`invoke_llm` 覆盖的 6 个调用点中 5 个不符合 instructor 的单结构化输出模型，整体替换净亏损，维持现状。
- 不迁移报告接地流水线（草拟→校验→修复→降级）：它是循环结束后的业务流程，不是横切关注点，不属于 middleware。
- 不在本 Feature 内做 OpenTelemetry 发射、评测体系、多租户与金额维度成本核算：各自独立立项。
- 不把两条研判循环作为长期产品能力：迁移期双跑只用于一次性风险控制，正式 API、Demo 与 CI 不提供 A/B 选择。

## 3. 总体方案

### 3.1 包结构与依赖方向

新增顶层包 `src/threat_agent/agent_middleware/`（暂驻本仓库，验证后可整体抽出独立发布）：

```
agent_middleware/
├── boundary.py      # BoundaryMiddleware + ToolBoundary 协议
├── budget.py        # BudgetMiddleware + BudgetPolicy + 熔断信号
├── compaction.py    # Reducer 协议 + 官方 SummarizationMiddleware 适配
└── events.py        # 中间件观测回调协议（拒绝、预算、压缩事件）
```

依赖铁律：包内禁止 import `contracts`、`judgment`、`case_management` 等业务模块，由 `test_architecture_dependencies.py` 新增断言强制。业务语义通过适配层接入（`bootstrap/middleware_bindings.py`——适配层同时组合 case_management 与 judgment，按依赖方向只能放在组合根 bootstrap）：把 `InvestigationBoundaryPort` 适配到 `ToolBoundary`，把 `Budget` 适配到 `BudgetPolicy`。

### 3.2 目标使用形态

```python
agent = create_agent(
    model, tools,
    middleware=[
        BoundaryMiddleware(policy=single_host_policy, context=run_scope),
        BudgetMiddleware(policy=case_budget, on_exhausted=degrade_to_report),
        summarization_middleware(reducer=domain_brief_reducer),
    ],
)
```

### 3.3 迁移验证与正式收敛

迁移期间曾使用脚本模型对比自建图与 middleware 路径的工具、边界与预算语义，以降低切换风险。该对拍已经完成其一次性职责；正式系统不保留双运行时选择器、runtime API 参数或持续双跑 CI。

当前验收改为锁定正式路径本身：框架中间件的边界、预算、压缩、报告降级和数据访问 Port 均须有自动化测试。详见 runtime-convergence-design.md。

## 4. 分项设计

### 4.1 BoundaryMiddleware（第一优先级）

现有能力与 middleware 钩子的映射：

| 现有实现 | middleware 映射 |
|---|---|
| 服务端注入 `ToolRuntimeContext`（身份不由模型侧提供） | 运行上下文工厂，随 middleware 构造注入 |
| `authorize_call` 调前授权 | `wrap_tool_call` 前半段 |
| `validate_result` 结果入账前校验 | `wrap_tool_call` 后半段 |
| `BoundaryDenied` 结构化拒绝回填模型（拒绝不伪装成空结果） | `wrap_tool_call` 返回结构化错误结果 |
| 授权引用账本（跨调用状态） | middleware `state_schema` 扩展状态 |

包内协议（领域无关）：

```python
class ToolBoundary(Protocol):
    def authorize(self, tool_name: str, arguments: Mapping[str, Any]) -> None: ...
    def validate(self, tool_name: str, result: Any) -> Any: ...
```

`authorize` 抛出结构化拒绝（错误码 + 标识，不含未授权对象内容）；`validate` 可拒绝或收敛结果。拒绝后同轮其余工具调用继续执行（与现有 denied trace 行为一致）。

**已确认（步骤 01 实测，langchain 1.2.10）**：`wrap_tool_call` 拿到的是序列化后的 `ToolMessage`（`content` + 可选 `artifact` 结构化字段），不是工具返回原值。业务侧 typed 校验在适配层按序列化形态进行（JSON Schema 级）；`artifact` 可承载结构化数据以减少序列化损失。状态更新以 `Command(update=...)` 返回，账本与工具消息落在同一次状态转移中（已由组件测试验证跨调用持久）。

### 4.2 BudgetMiddleware（第二优先级）

预算维度与钩子映射：

| 维度 | 钩子 | 行为 |
|---|---|---|
| 迭代 | `wrap_model_call` | 递增；触顶则阻止后续模型调用 |
| 工具调用 | `wrap_tool_call` | 递增；触顶则拒绝后续调用并计入结构化拒绝 |
| token | `wrap_model_call` | 按 usage 累计；不足时阻止下一次模型调用 |
| 报告重判 | 不进 middleware | 属报告流水线语义，留在业务层 |

超额语义继承现有设计：预算耗尽不是异常路径。熔断以结构化信号抛出，业务在 agent 调用外层捕获后执行注册的 `on_exhausted` 降级出口（现有系统对应"预算耗尽仍用已查数据出报告"）。组件包只发熔断信号，降级动作由业务注入。

金额维度与多租户配额不在本 Feature 范围。

### 4.3 压缩对齐（第三优先级）

不实现独立压缩链。以官方 `SummarizationMiddleware` 为壳，本包只交付：

- `Reducer` 协议：`def reduce(self, tool_name: str, result: Any) -> Any`，对应现有 `brief_result` 的领域感知降采样（保留携带调查信号的字段，丢弃大块原文）；
- `ReducerMiddleware`：在工具结果进入会话历史前做确定性降采样，原文保留在 ToolMessage `artifact`（业务侧另有 typed 账本全量留档）；
- 官方机制（触发水位、摘要生成、失败回退）不重复实现，跟随官方演进。

**已确认（步骤 04 实测，langchain 1.2.10）**：

1. 官方 `SummarizationMiddleware` 没有逐工具结果的处理点，摘要以带官方前缀的 human 消息注入；因此 reducer 以独立可组合中间件交付，与官方壳叠加使用（边界中间件必须排在外层，先验原始结果再做降采样）。
2. 现有系统里 `brief_result` 只用于演示事件流，planner 回放历史是全量原文直到水位折叠；即"入历史前确定性降采样"对 create_agent 路径是新增能力，业务适配层直接复用 `brief_result` 实现 reducer。
3. 官方摘要模型需可重复应答（单发迭代器耗尽会降级为错误文本），接线时使用常驻模型。

## 5. 设计决策

1. **组件包暂驻本仓库**：双跑等价验证需要真实案件数据与现有实现对拍，先内部验证、后抽包独立发布，避免空转建仓。
2. **策略接口进包、策略实现留业务侧**：单主机边界等安全语义进入组件包会破坏复用性，也让包的测试依赖领域数据。
3. **压缩对齐官方而非自研**：机制层面与官方维护力量赛跑必输；差异化只在 reducer，工作量最小、可白蹭官方改进。
4. **预算先做三维（迭代 / 工具调用 / token）**：金额与租户配额依赖成本核算与身份体系，属商业化后续项。
5. **重试维持现状**：见非目标第一条。

## 6. 验收门槛

- 架构依赖测试新增断言：`agent_middleware` 不 import 任何业务模块；
- BoundaryMiddleware：未授权调用被结构化拒绝且错误码稳定可测；拒绝后同轮其余工具调用继续；未授权对象内容不出现在模型可见的消息中；
- BudgetMiddleware：三维预算各自触顶行为符合上表；耗尽走 `on_exhausted` 降级出口，不抛未捕获异常；
- 压缩：注入 reducer 后，超阈值运行的上下文 token 估算受控，且压缩路径的消息序列被集成测试锁定；
- 正式路径：Demo、API 与运行服务只组装 MiddlewareJudgmentRunner，旧 runtime 参数被严格拒绝；
- 现有全量测试通过。
