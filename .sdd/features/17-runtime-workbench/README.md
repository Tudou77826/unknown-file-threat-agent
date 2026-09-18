# Runtime Workbench

把"架构阶段的演示壳"升级为常驻运行工作台：向上是使用面（建案、运行视图、审批台、报告审阅），向内是调测面（三栏轨迹、checkpoint 恢复重跑、知识面板），可观测走 Langfuse 旁路，评测经运行面适配 Feature 16 框架。

核心不变式：**平台不新增业务层**——所有展示数据来自既有账本 / 检查点 / read model，所有操作走既有框架入口；演示页退役为只读剧本模式。

选型依据（LangGraph Server 不迁移的原因、Langfuse / Agent Inbox / DSH 对比）：[`outputs/runtime-platform/platform-selection.md`](../../../outputs/runtime-platform/platform-selection.md)。

## 文档

- [design.md](design.md)：背景与资产盘点、总体架构、模块划分、核心契约、外部组件边界、界面信息架构、里程碑与风险。
- [implementation-plan.md](implementation-plan.md)：四个实施步骤与验证门槛。

## 状态

设计待审批；尚未实现。
