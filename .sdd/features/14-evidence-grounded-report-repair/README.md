# Evidence-Grounded Report Repair

本 Feature 修复正式报告可能“删除失效引用但保留原结论”的可信性缺口。引用、事实陈述与 Verdict 被视为同一语义单元：引用校验失败时，系统要求 LLM 在授权证据白名单内重新研判，而不是为原结论替换或删除引用；确定性代码负责最终校验，修复耗尽后只允许发布明确标记的证据不足兜底报告。

该设计同时分离候选报告、校验、重新研判和正式发布职责，使报告链路完成需求后比当前结构更清晰。

## 文档

- [design.md](design.md)：问题、发布不变量、重新研判流程、职责边界和验收门槛。

## 状态

产品方向已确认。已实施：`ReportGroundingValidator`（8 个稳定问题码）、`ReportRepairCoordinator`（授权证据白名单重新研判）、`VerdictEvidenceGate`（能力只从 Verdict 实际引用计算）、`ReportPublisher`（唯一正式报告构造点）与 `DeterministicFallbackBuilder`（`fallback + insufficient_evidence` 兜底）；`_sanitize_report` 静默修复路径删除；`publication_status` 进入契约并约束 Response Advisory 高影响建议与 Presentation 展示。单元与架构测试通过；LLM 检测回归待带模型环境运行。
