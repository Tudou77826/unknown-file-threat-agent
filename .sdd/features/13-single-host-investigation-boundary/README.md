# Single-Host Investigation Boundary

本 Feature 为初期后门与勒索调查建立单主机可信边界：系统固定使用服务端单租户标识，每个案件只允许查询告警主机，关闭跨主机 Scope Expansion；所有调查工具统一执行主机、时间、数据域、实体来源和运行引用校验。

跨主机线索可以作为未解决问题进入报告，但系统不得查询目标主机，也不得将传播表述为已确认事实。通用 Scope 数据契约保留；仅服务于未交付跨主机能力的运行节点和内部模型不作为预留代码保留，未来通过独立 Feature 扩展。

## 文档

- [design.md](design.md)：边界模型、工具授权、检测影响、兼容策略与验收标准。

## 状态

关键产品决策已确认：初期关闭跨主机调查，租户鉴权与 RBAC 后置。已实施：`InvestigationBoundaryPort` 统一包围全部调查工具（调用前授权 + 结果后校验）、`SingleHostBoundaryPolicy`、`explore_entity` 实体授权与主机归属修复、跨主机扩域/审批路径删除、服务端租户注入与 `INVESTIGATION_LOOKBACK_HOURS` 回看配置。单元与架构测试通过；真实 LLM 端到端回归已跑通 C2 恶意/良性 L3 双数据集（likely_malicious / likely_benign，均 grounded 发布，零边界拒绝，跨主机线索仅进未解决问题）。勒索数据集与完整 8.2 矩阵待后续补充。
