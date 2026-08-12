# Platform Architecture Migration Implementation Plan

## 1. 执行方式

实施分为八个连续步骤。每一步只在前一步验证通过后开始；旧入口保留到最终切换，避免迁移中途失去可运行版本。

计划已执行完成。验证结果记录稳定验收事实，不包含调试过程。

| 步骤 | 交付结果 | 依赖 | 状态 |
|---:|---|---|---|
| 01 | 基线、契约与运行时依赖冻结 | 无 | 已完成 |
| 02 | 数据底座查询端口与本地适配器 | 01 | 已完成 |
| 03 | LangGraph 研判子图与现有语义对齐 | 02 | 已完成 |
| 04 | 父图、Checkpoint 与 Scope 中断恢复 | 03 | 已完成 |
| 05 | RAG 接口占位与无实现降级 | 04 | 已完成 |
| 06 | 处置建议 LLM 子图 | 05 | 已完成 |
| 07 | 案件读模型、API 与只读展示 | 06 | 已完成 |
| 08 | 默认入口切换、清理与整体验收 | 07 | 已完成 |

## 2. 步骤说明

### 01：基线、契约与运行时依赖冻结

目标是建立可比较的迁移基线，不改变研判结果。

实施内容：

- 记录现有 Case 的结构化输出和测试基线；
- 将 LangGraph 及其 Checkpointer 依赖显式写入项目配置，验证与 LangChain 结构化模型接口兼容；
- 在代码中定义 `InitialCase`、`EvidenceQuery`、`JudgmentResult`、`KnowledgeResult`、`ResponsePlan` 和 `CaseReadModel` 的版本化契约；
- 增加契约序列化、反序列化和版本拒绝测试。

验证门槛：现有全部测试通过；契约可进行 JSON 往返；未支持的主版本被明确拒绝。

回滚点：仅删除新增契约和显式依赖，不影响旧运行入口。

### 02：数据底座查询端口与本地适配器

目标是使调查流程不再依赖 Case 目录和 `InvestigationState` 查询参数。

实施内容：

- 新增 `EvidenceQueryPort`、`QueryContext`、分页和 Coverage 契约；
- 用适配器包装现有 `FixtureEvidenceRepository` 与 `JsonlEventRepository`；
- Tool 只依赖查询端口，Scope、时间和预算通过显式上下文传入；
- 保留旧 Repository 接口的兼容包装，避免同时改动所有调用方。

验证门槛：同一查询经旧 Repository 和新端口返回等价 Evidence/Coverage；越界 Scope 被拒绝；空结果与数据不可见可区分。

回滚点：Tool 切回兼容包装，旧 Repository 保持不变。

### 03：LangGraph 研判子图与现有语义对齐

目标是用图取代 `InvestigationEngine.run()` 的手写循环，同时保持现有研判结果。

实施内容：

- 定义 `JudgmentGraphState`、字段 reducer 和旧状态转换器；
- 将规划、动作校验、证据查询、确定性分析、Scope 请求、结束判断、Verdict 校验和修复拆为图节点；
- 使用条件边表达动作类型、失败处理、预算耗尽和 Verdict 修复；
- Planner 改用受 Schema 约束的结构化输出，移除自由文本 JSON 截取路径；
- 旧 Engine 与新图通过运行配置并存，CLI 暂不切换默认值。

验证门槛：全部黄金 Case 在 Verdict、威胁类型、关键 Finding、证据引用和限制方面与旧引擎等价；节点路由、reducer、预算和失败分支具有单元测试。

回滚点：关闭 LangGraph 运行配置，继续使用旧 Engine。

### 04：父图、Checkpoint 与 Scope 中断恢复

目标是建立案件级运行边界和可恢复流程。

实施内容：

- 新增 `CaseGraphState` 和父图，将研判子图作为独立节点接入；
- 以 `tenant_id/case_id/run_id` 作为线程标识配置 Checkpointer；
- 开发环境提供内存与 SQLite 实现；
- 将 Scope 扩展改为 LangGraph interrupt，支持批准、拒绝和恢复；
- 为外部查询和状态提交生成稳定幂等键。

验证门槛：进程重启后可以从持久化检查点恢复；批准与拒绝路径均可完成；恢复不会重复已提交的工具结果；不同租户和案件状态隔离。

回滚点：使用无持久化的研判子图入口，旧 Engine 仍可运行。

### 05：RAG 接口占位与无实现降级

目标是稳定未来 RAG 的接入边界，但不提供任何知识检索实现。

实施内容：

- 定义最小 `KnowledgeQuery`、`KnowledgeResult` 和 `KnowledgeRetrievalPort`；
- 提供 Null Adapter，明确返回 `not_configured`，不伪造空知识命中；
- 为研判图和处置图保留可选知识上下文字段与调用节点；
- 保证 Knowledge ID 与 Evidence ID 类型隔离；
- 不增加文档加载、分块、Embedding、索引、检索、ACL 或重排依赖。

验证门槛：Null Adapter 行为稳定；两个循环在 `not_configured` 时可完成；Knowledge ID 无法通过 Verdict 的 Evidence 引用校验；项目不存在向量库和 Embedding 运行依赖。

回滚点：移除可选知识调用节点，端口契约可独立保留。

### 06：处置建议 LLM 子图

目标是完成第二个 LLM 循环，输出建议但不执行动作。

实施内容：

- 定义处置状态、候选动作、风险、前置条件、回滚、验证和缺失上下文模型；
- 实现资产/业务上下文查询、LLM 动作规划、Policy 校验、修复和结束节点；知识端口返回不可用时生成保守方案并记录 `missing_context`；
- 处置子图只接收已发布 `JudgmentResult`，使用独立模型、提示、工具和预算；
- 将需要审批的方案传递给父图 interrupt；
- 增加确定性 Fake LLM 以覆盖循环和异常分支。

验证门槛：处置循环不能修改研判事实；每个动作具有依据、影响、前置条件、审批类别、回滚和验证步骤；缺少信息时输出 `missing_context`，不得臆造资产状态或组织政策。

回滚点：父图跳过处置子图，只发布 `JudgmentResult`。

### 07：案件读模型、API 与只读展示

目标是用稳定输出契约展示完整案件，而不是暴露图内部状态。

实施内容：

- 从已提交案件状态投影 `CaseReadModel`；
- 重构 JSON/Markdown 输出，使其消费读模型并保持当前主要字段兼容；
- 提供只读案件 API 和服务端页面，展示结论、攻击路径、证据、Coverage、调查时间线、处置建议、审批状态和限制；知识引用字段作为可选占位；
- 审批操作只调用案件恢复接口，不允许直接修改 Checkpoint；
- 为 API Schema、空状态、超长内容和 HTML 转义增加测试。

验证门槛：展示层不导入 LangGraph State 或读取 Case 文件；JSON/Markdown 回归通过；页面可从本地完整 Case 生成并正确处理敏感文本转义。

回滚点：保留旧报告生成器和 CLI 输出，新 API/页面可独立关闭。

### 08：默认入口切换、清理与整体验收

目标是让新架构成为唯一默认运行路径，并移除已经证明重复的流程代码。

实施内容：

- CLI 默认切换到父图，保留一个有明确弃用期的旧引擎诊断入口；
- 完成所有 Case 的端到端双循环运行和输出验证；
- 验证中断恢复、幂等、权限隔离、RAG 未配置降级、预算和失败处理；
- 删除手写循环、重复 JSON 解析和失去调用方的兼容代码；
- 更新 `.sdd` 状态、运行说明和实现映射。

验证门槛：全量自动测试通过；离线演示不依赖外部数据湖、向量数据库或真实模型；配置真实模型时两个 LLM 循环可完成冒烟运行；项目内不存在默认入口对旧 Engine 的依赖。

回滚点：在删除旧 Engine 前保留最后一个可切换版本；清理动作只在新入口完整验收后执行。

## 3. 目标代码演进

目录按能力落地逐步创建，不做一次性搬迁：

| 步骤 | 主要新增或迁移位置 |
|---:|---|
| 01 | `src/threat_agent/contracts/`、项目依赖配置 |
| 02 | `src/threat_agent/data_foundation/`、Repository 适配器 |
| 03 | `src/threat_agent/judgment/` 的领域、应用、端口和适配器 |
| 04 | `src/threat_agent/case_management/` 的父图、Checkpoint 和结果提交 |
| 05 | `src/threat_agent/knowledge/` 的端口与 Null Adapter |
| 06 | `src/threat_agent/response_advisory/` 的领域、子图和上下文端口 |
| 07 | `src/threat_agent/presentation/` 的只读 Store、API 与契约序列化 |
| 08 | `src/threat_agent/bootstrap/`、独立模型配置和架构依赖检查 |

## 4. 验证体系

每一步执行相同的基础门槛，并增加该步骤的专项验证：

1. 静态检查：导入、Schema、Markdown 链接和无效引用。
2. 单元测试：Reducer、Policy、Validator、端口和投影函数。
3. 契约测试：各适配器对同一端口返回一致语义。
4. 图测试：节点路由、预算、失败、interrupt、resume 和 checkpoint。
5. 黄金 Case：保持 Verdict、Finding 和证据引用语义。
6. 端到端测试：数据查询、研判、RAG 未配置降级、处置和展示全链路。
7. 真实模型冒烟：有模型凭据时运行，不作为离线 CI 的硬依赖。

若某一步未达到验证门槛，不开始下一步，也不以修改期望结果掩盖语义退化。

## 5. 计划审批项

本计划请求确认：

1. 按上述八步顺序逐项实施和验证。
2. 旧 Engine 保留到第 08 步，不在 LangGraph 研判图尚未等价时删除。
3. RAG 本次只保留接口和 Null Adapter，全部具体实现后续单独设计。
4. 展示首版采用只读 API 与服务端页面，不建设复杂前端应用。
5. 第 08 步才切换默认入口并清理兼容代码。

## 6. 验收结果

- 102 项自动测试通过，覆盖 18 个黄金 Case和模块依赖方向检查。
- `CaseGraph` 原生挂载研判与处置建议编译子图，子图沿用父图持久化语义。
- 公共契约、数据底座和展示层不再依赖 `InvestigationState`。
- LangGraph 研判结果与迁移前 Verdict、威胁类型、关键 Finding 和证据引用等价。
- SQLite Checkpoint 可由新父图实例恢复，Scope 与处置审批均使用 interrupt。
- RAG 未配置时双循环正常完成，且不存在向量库或 Embedding 依赖。
- 确定性端到端冒烟生成 `JudgmentResult`、`ResponsePlan`、JSON/Markdown 报告、API 和只读页面。
- LLM 路径使用模型原生结构化输出；真实供应商调用依赖部署环境凭据，不属于离线自动验收。
