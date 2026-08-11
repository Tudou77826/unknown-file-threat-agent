# Cross-Feature Contracts

## 1. 契约关系

| 提供方 | 消费方 | 契约 |
|---|---|---|
| Case Governance | Judgment Engine | `InitialCase`、调用身份、Scope、运行预算 |
| Data Foundation | Judgment Engine | `EvidenceQuery` → `EvidencePage + Coverage` |
| RAG Knowledge | Judgment Engine | `KnowledgeQuery` → 带引用的调查知识 |
| Judgment Engine | Response Advisory | `JudgmentResult` |
| Data Foundation | Response Advisory | 资产、业务、身份和控制面上下文 |
| RAG Knowledge | Response Advisory | SOP、审批策略、操作手册和历史经验 |
| Response Advisory | Case Governance | `ResponsePlan` |
| Case Governance | Execution System | 经批准的 `ExecutionRequest` |

## 2. 通用要求

- 所有契约必须包含 `schema_version`、`tenant_id`、`case_id`、`created_at` 和来源身份。
- 时间统一使用带时区的 UTC 时间；原始时间和规范化结果均可追溯。
- ID 在租户范围内稳定，跨 Feature 不得重新解释同一 ID。
- 返回空集合时必须同时返回 Coverage，区分“完整范围内无结果”和“数据不可见”。
- 契约演进默认向后兼容；破坏性变化必须提升主版本并提供迁移策略。
- 自然语言摘要不能替代结构化字段或证据引用。

详细模型由提供该契约的 Feature 维护。
