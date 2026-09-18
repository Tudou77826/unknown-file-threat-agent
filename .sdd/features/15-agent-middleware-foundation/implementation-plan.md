# Agent Middleware Foundation Implementation Plan

> 本文记录组件抽取与迁移期间的已完成实施步骤。当前运行时决策、支持边界和验收标准以 runtime-convergence-design.md 为准；双跑不是持续运行能力。

## 1. 执行结论

实施分为五个连续步骤，按差异化强度排序：边界防护最先（建立组件包骨架与依赖铁律），预算次之（复用第一步建立的扩展状态与降级出口套路），压缩最后（依赖官方中间件，只做协议与适配）。这些步骤已经完成，曾用于为正式切换建立证据；当前 Demo 与 API 已固定为 middleware 路径。

| 步骤 | 交付结果 | 依赖 |
|---:|---|---|
| 01 | 组件包骨架 + BoundaryMiddleware + 依赖铁律断言 | 无 |
| 02 | 边界业务适配 + 双跑等价验证（边界路径） | 01 |
| 03 | BudgetMiddleware + 降级出口 + 双跑等价验证（预算路径） | 02 |
| 04 | Reducer 协议 + 官方 SummarizationMiddleware 适配 + 压缩路径集成测试 | 03 |
| 05 | 双跑全量对比评估报告与切换建议 | 04 |

本计划不替换 LLM 分级重试、不迁移报告接地流水线、不做 OpenTelemetry / 评测 / 多租户 / 金额维度预算。

## 2. 实施步骤

### 01：组件包骨架与 BoundaryMiddleware

目标：建立 `src/threat_agent/agent_middleware/` 包，交付第一件能力并固化依赖方向。

实施内容：

- 定义 `ToolBoundary` 协议（`authorize` / `validate`）与结构化拒绝模型（错误码 + 标识，不含未授权内容）；
- 实现 `BoundaryMiddleware`：`wrap_tool_call` 前半段授权、后半段校验，拒绝以结构化错误结果返回；授权账本走 middleware 扩展状态；
- 定义 `events.py` 观测回调协议（拒绝事件），供业务接运行事件流；
- `test_architecture_dependencies.py` 新增断言：`agent_middleware` 不 import 业务模块；
- 用假策略（内存规则表）完成组件级行为测试：未授权拒绝、错误码稳定、同轮后续调用继续、未授权内容不进消息。

验证门槛：

- 组件测试不依赖任何业务模块即可运行；
- 拒绝后的工具结果可被下一轮模型调用消费（结构化错误形态）；
- 全量回归通过。

### 02：边界业务适配与等价验证

目标：把现有单主机边界接到组件包，证明middleware 版与现有图在边界行为上等价。

实施内容：

- 新增 `judgment/adapters/middleware_bindings.py`：`InvestigationBoundaryPort` → `ToolBoundary` 适配；
- 实测并记录 `wrap_tool_call` 拿到的结果形态（原值或序列化 ToolMessage），据此确定 `validate` 的校验强度；若为序列化形态，在适配层标注降级并补充 JSON Schema 级校验测试；
- 以 `cases/c2_malicious`、`cases/c2_benign` 为基准构建双跑对比脚本，比对工具调用序列与拒绝码序列。

验证门槛：

- 两个基准案件下，越界调用拦截点与错误码序列与现有图完全一致；
- 全量回归通过。

### 03：BudgetMiddleware 与降级出口

目标：交付三维预算熔断，超额走业务降级出口而非异常。

实施内容：

- 定义 `BudgetPolicy`（三维上限与计数）与熔断信号类型；
- 实现 `BudgetMiddleware`：迭代与 token 在 `wrap_model_call`，工具调用在 `wrap_tool_call`；预算事件走观测回调；
- `wrap_agent_call` 捕获熔断信号，调用业务注入的 `on_exhausted`；
- 业务适配：现有 `Budget` 语义接到 `BudgetPolicy`，"预算耗尽仍出报告"接到 `on_exhausted`；
- 双跑对比扩展预算维度：两套实现的预算消耗与触顶行为一致。

验证门槛：

- 三维各自触顶时行为符合设计表（阻止 / 拒绝 / 降级），无未捕获异常；
- 预算耗尽案件的最终报告与现有图一致（走降级报告路径）；
- 全量回归通过。

### 04：压缩对齐

目标：以官方 SummarizationMiddleware 为壳接入可插拔 reducer，锁定压缩路径消息语义。

实施内容：

- 定义 `Reducer` 协议与基于现有 `brief_result` 字段表的默认实现（实现留在业务适配层，协议在包内）；
- 适配函数：把 reducer 接到官方中间件对工具结果消息的处理点；
- 集成测试锁定：超阈值运行时的消息序列（摘要 + 保留范围）、reducer 注入后的 token 估算受控、官方中间件的消息清空行为差异被显式断言；
- 双跑对比扩展压缩路径：中等长度案件（触发压缩不触发预算）两套实现的调查行为一致。

验证门槛：

- 压缩路径消息序列有集成测试锁定，官方中间件升级时差异可见；
- 双跑等价覆盖压缩路径；
- 全量回归通过。

### 05：双跑全量对比与切换建议

目标：产出评估报告，作为是否将 demo 路径切换到 middleware 版的审批输入。

实施内容：

- 扩展基准案件集（至少覆盖恶意、良性、预算耗尽、越界拦截四类路径）；
- 全量双跑对比：verdict、publication_status、工具调用序列、拒绝码序列、预算消耗、模型调用次数；
- 评估报告：等价性结论、性能与成本差异、遗留差异清单（如 finish 动作排序等现有图特有编排行为）、切换建议。

验证门槛：

- 评估报告覆盖全部基准案件，无未解释差异；
- 切换决策不在本步骤内执行，单独审批。
