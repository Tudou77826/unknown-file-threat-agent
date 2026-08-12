# Response Advisory

处置建议 Feature 使用独立 LLM 循环，把只读 `JudgmentResult` 转换为有依据、有条件、可审批和可回滚的 `ResponsePlan`。它不直接执行动作。

## 文档

- [requirements.md](requirements.md)
- [design.md](design.md)
- [response-plan-model.md](response-plan-model.md)
- [action-policy.md](action-policy.md)
- [verification.md](verification.md)

## 当前状态

当前已实现独立 LangGraph 处置建议子图、结构化 LLM Planner、动作 Policy、修复预算和 `ResponsePlan`。方案只提供建议并进入审批中断，不执行实际动作。
