# Case Governance

Case Governance 管理案件和 Agent 运行生命周期，并承载身份、Scope、审批、执行边界和审计。它不决定威胁结论，也不生成处置方案。

## 文档

- [requirements.md](requirements.md)
- [design.md](design.md)
- [case-model.md](case-model.md)
- [authorization.md](authorization.md)
- [verification.md](verification.md)

## 当前状态

当前已实现案件父图、内存/SQLite Checkpoint、租户化线程标识，以及 Scope 和处置方案审批中断。生产案件服务、队列、身份系统和真实执行集成仍待建设。
