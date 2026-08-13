# Cross-Feature Contracts

## 1. 契约关系

| 提供方 | 消费方 | 契约 |
|---|---|---|
| Case Governance | Judgment Engine | `InitialCase`、调用身份、Scope、运行预算 |
| Data Foundation | Judgment Engine | 活动域查询 → `ActivityQueryResult`（接口定义、执行边界、Activity、EvidenceReference） |
| RAG Knowledge | Judgment Engine | `KnowledgeQuery` → 带引用的调查知识 |
| Judgment Engine | Response Advisory | `JudgmentResult` |
| Judgment Engine | Presentation | `InvestigationReport` |
| Data Foundation | Response Advisory | 资产、业务、身份和控制面上下文 |
| RAG Knowledge | Response Advisory | SOP、审批策略、操作手册和历史经验 |
| Response Advisory | Case Governance | `ResponsePlan` |
| Case Governance | Execution System | 经批准的 `ExecutionRequest` |

## 2. 通用要求

- 全局数据契约必须包含 `schema_version`、`tenant_id`、`created_at` 和来源身份，不得伪造 `case_id`；案件边界契约额外包含 `case_id`。
- 时间统一使用带时区的 UTC 时间；原始时间和规范化结果均可追溯。
- ID 在租户范围内稳定，跨 Feature 不得重新解释同一 ID。
- 查询结果必须携带接口定义和实际执行边界；空集合只表示本次查询返回零条记录，不由数据层解释原因或质量。
- RawRecord 和 NormalizedActivity 不属于案件；EvidenceReference 才建立案件、运行、查询与底层 Activity 的引用关系。
- Activity 查询按域提供强类型端口；存储 Adapter 返回接口定义、实际执行 Scope、分页和实际记录，不返回数据充分性评价。
- `EvidenceBundle.coverage` 不进入新的 LLM 调查和报告上下文；接口定义与实际查询边界由 Activity 查询结果提供。
- Judgment LLM 只直接使用 `query_activities`、`explore_entity`、`get_raw_records` 和 `calculate_activity_metrics`；Tool Gateway 注入案件运行上下文并调用内部强类型端口。
- `InvestigationReport` 的威胁结论由 LLM 生成；确定性发布校验只检查引用存在性、实际 Scope 和候选关系状态。
- 调查运行、运行事件、审计事件和发布产物通过运行存储端口持久化；Checkpoint 只负责 LangGraph 状态恢复，不作为运行事实或审计事实来源。
- 可观测事件与审计事件按 `run_id`、顺序号和关联 ID 重建处理链路；日志保存受控摘要和引用，不保存 API Key、完整 Prompt 或完整模型输入。
- `POST /api/investigations` 创建最小调查运行，`GET /api/investigations/{run_id}` 返回持久化运行、事件、正式调查报告和独立处置方案。
- LLM 根据接口字段、关联键、查询范围、分页信息和返回活动自行判断数据支持程度；数据层不得输出评价性质的充分性结论。
- 首版发布前允许直接修正契约和调用链，不承诺历史开发版本兼容；首版发布后的契约演进策略另行定义。
- 自然语言摘要不能替代结构化字段或证据引用。

详细模型由提供该契约的 Feature 维护。
