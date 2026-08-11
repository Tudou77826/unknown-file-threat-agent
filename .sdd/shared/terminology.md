# Terminology

| 术语 | 定义 |
|---|---|
| InitialCase | 启动调查所需的最小告警、主体和时间范围，不代表全部证据 |
| Evidence | 来自数据源的原子观测，包含来源、时间、主体、状态和原始引用 |
| Claim | 上游告警或外部材料提出、尚未独立验证的陈述 |
| Fact | 由明确 Evidence 直接验证的事实 |
| Finding | 基于 Evidence 和 Fact 通过分析得到的安全含义 |
| Relation | 两个实体之间由 Evidence 支撑的关系边 |
| Coverage | 数据源可用性、时间覆盖、完整性、截断和限制 |
| Hypothesis | 等待证据支持或反驳的案件解释 |
| EvidenceGap | 为回答调查问题仍缺少的证据 |
| Verdict | 对案件威胁性质和置信程度的结构化结论 |
| JudgmentResult | 研判引擎向下游交付的 Verdict、证据、范围、影响和限制集合 |
| ResponsePlan | 处置建议引擎输出的候选动作、条件、影响、审批、回滚和验证集合 |
| KnowledgeItem | 经版本、来源、ACL 和有效期管理的 RAG 知识单元 |
| Scope | 当前身份获准调查的数据、主机、实体和时间边界 |

同一概念在代码和文档中应使用同一名称。新增术语必须先明确与现有术语的差异。
