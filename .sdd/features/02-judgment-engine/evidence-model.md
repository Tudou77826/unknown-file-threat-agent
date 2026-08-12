# Judgment Evidence Model

## 语义层级

```text
Claim       上游或知识材料提出但未验证的说法
Evidence    数据源原子观测
Fact        Evidence 直接确认的事实
Finding     基于 Evidence/Fact 的安全分析结果
Relation    实体之间有 Evidence 支撑的关系
Verdict     对完整案件的结论
```

层级不可逆向替代：LLM 解释不是 Fact，知识库文档不是案件 Evidence，告警标签不是已验证 Finding。

## Evidence 要求

Evidence 必须包含稳定 ID、类型、来源、时间、主体引用、状态、限制和原始引用。敏感字段可以受控隐藏，但不得失去审计定位能力。

## JudgmentResult

至少包含：

```text
schema_version
case_id
verdict
threat_types
confidence
affected_entities
attack_path
supporting_refs
contradicting_refs
known_impact
unresolved_scope
coverage_limitations
model_and_rule_versions
```

`JudgmentResult` 是向处置建议模块交接的只读快照。后续处置风险判断不能修改其中的 Fact 和 Finding。
