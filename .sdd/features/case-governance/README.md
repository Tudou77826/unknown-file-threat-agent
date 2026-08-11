# Case Governance

Case Governance 管理案件和 Agent 运行生命周期，并承载身份、Scope、审批、执行边界和审计。它不决定威胁结论，也不生成处置方案。

## 文档

- [requirements.md](requirements.md)
- [design.md](design.md)
- [case-model.md](case-model.md)
- [authorization.md](authorization.md)
- [verification.md](verification.md)

## 当前状态

当前代码具备进程内 Scope、Budget、ToolCall 和 ScopeExpansion 模型，但没有持久化案件服务、队列、用户身份、审批工作流或真实执行集成。
