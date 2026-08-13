# Terminology

| 术语 | 定义 |
|---|---|
| InitialCase | 启动调查所需的最小告警、主体和时间范围，不代表全部证据 |
| RawRecord | 从来源系统接收并由本系统保存的原始记录信封及载荷引用，不属于任何案件 |
| NormalizedActivity | 将来源记录转换为统一活动 Schema 后形成的客观活动，是安全数据查询的事实源，不包含平台最终恶意定性 |
| EntityIdentity | 平台对 Host、Process、File 等对象的时态身份及来源别名，不能仅用 PID、IP、路径或主机名认定同一实体 |
| ObservedRelation | 由 Activity 支撑的实体时态关系；不确定关系必须保持 candidate 状态 |
| EvidenceReference | 某次案件运行在明确查询和 Scope 下对底层 Activity 的不可变引用 |
| Evidence | 研判阶段使用的案件事实载体；数据底座以 EvidenceReference 表达案件对底层 Activity 的引用 |
| Claim | 上游告警或外部材料提出、尚未独立验证的陈述 |
| Fact | 由明确 Evidence 直接验证的事实 |
| Finding | 基于 Evidence 和 Fact 通过分析得到的安全含义 |
| Relation | 研判结果中由 Evidence 支撑的案件关系边，不等同于数据底座的 ObservedRelation |
| QueryInterfaceDefinition | 数据查询接口向 LLM 公开的活动类型、字段语义、过滤条件、关联键、排序和分页等稳定约束 |
| QueryExecutionBoundary | 一次查询实际应用的主机、实体、时间、过滤条件、来源、返回数量和分页游标，不包含数据质量评价 |
| Hypothesis | 等待证据支持或反驳的案件解释 |
| EvidenceGap | 为回答调查问题仍缺少的证据 |
| Verdict | 对案件威胁性质和置信程度的结构化结论 |
| JudgmentResult | 研判引擎向下游交付的 Verdict、证据、范围、影响和限制集合 |
| InvestigationReport | 面向用户发布的版本化调查报告，由 LLM 基于查询接口约束和实际数据生成结论说明，并通过引用和 Scope 校验 |
| InvestigationRun | 一次可持久化查询的调查运行及其当前状态，不等同于完整案件管理对象 |
| ResponsePlan | 处置建议引擎输出的候选动作、条件、影响、审批、回滚和验证集合 |
| KnowledgeItem | 经版本、来源、ACL 和有效期管理的 RAG 知识单元 |
| Scope | 当前身份获准调查的数据、主机、实体和时间边界 |

同一概念在代码和文档中应使用同一名称。新增术语必须先明确与现有术语的差异。
