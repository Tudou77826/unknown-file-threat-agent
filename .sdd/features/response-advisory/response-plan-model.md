# ResponsePlan Model

## 顶层字段

```text
schema_version
case_id
judgment_result_id
objective
recommended_actions
alternative_actions
actions_not_recommended
missing_context
residual_risk
knowledge_refs
created_by
created_at
```

## ResponseAction

每个动作至少包含：

```text
action_id
action_type
target_refs
priority
rationale_refs
policy_refs
preconditions
expected_effect
business_impact
forensic_impact
reversibility
approval_class
rollback
validation_steps
expires_at
```

目标使用稳定实体 ID，不允许只用自然语言描述“感染主机”。建议必须区分立即动作、后续动作和仅在条件满足时执行的动作。
