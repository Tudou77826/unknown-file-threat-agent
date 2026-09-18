# Agent Middleware Foundation

把调查系统里已验证的三项横切能力——工具调用边界防护、多维预算熔断、上下文压缩降采样——从自建图节点重构为 LangChain 1.x middleware 形态的组件包，使任何 `create_agent` 构建的 Agent 可以通过一行挂载获得这些能力，且组件包本身不携带安全领域语义。

三项能力按差异化强度排序交付：边界防护（开源空白，官方不会做业务语义版本）→ 预算熔断（稀缺但可被通用件替代）→ 压缩对齐官方 SummarizationMiddleware（机制无差异化价值，增量只做可插拔 reducer）。

## 文档

- [design.md](design.md)：背景、目标、分项设计与关键决策。
- [implementation-plan.md](implementation-plan.md)：五个实施步骤与验证门槛。
- [runtime-convergence-design.md](runtime-convergence-design.md)：正式运行时、调查数据 Port 与验收边界。
- [verification.md](verification.md)：当前正式路径的验证基线。

## 状态

正式在线调查已收敛到 create_agent + middleware 路径。Demo 页面、调查 API 和运行读模型不再暴露运行时选择；CaseGraph 仅消费研判子图 Port。工具网关通过 InvestigationDataPort 访问数据，不再绑定 SQLite。

历史双跑阶段用于降低切换风险，但不再作为用户可操作的 A/B 产品能力。当前范围、兼容性行为和验收标准以 [runtime-convergence-design.md](runtime-convergence-design.md) 为准。
