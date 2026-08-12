# Case Model

案件顶层至少包含：

```text
tenant_id
case_id
case_type
status
severity
owner
initial_case
scope
judgment_runs
judgment_result
response_advisory_runs
response_plans
approvals
executions
audit_refs
version
created_at
updated_at
```

## 运行记录

每次模型或工具运行是独立记录，包含输入引用、输出引用、模型/工具版本、预算、状态、错误和耗时。大体量 Evidence 存在数据底座，案件只保存稳定引用和必要快照。

## 状态原则

`JudgmentResult` 和已批准的 `ResponsePlan` 采用不可变版本。重新研判或重新建议产生新版本，不覆盖旧版本。
