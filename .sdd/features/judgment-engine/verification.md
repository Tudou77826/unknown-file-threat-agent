# Judgment Engine Verification

## 回归集

每个场景至少维护：

- 完整恶意链；
- 合法或批准行为；
- 数据不足；
- 关键动作尝试但未成功；
- 只有弱相关线索的反例。

## 检查项

- 不存在无 Evidence 引用的 Fact、Finding 或 Relation。
- LLM 不能选择未授权工具或越过 Scope。
- Planner 更换后，确定性结论门槛保持稳定。
- Coverage 不完整不会被解释为行为不存在。
- 重复查询、无收益循环和修复次数受预算约束。
- `JudgmentResult` 满足跨 Feature 契约。

当前 59 项测试和 18 个 Case 是初始基线；新增数据模型、模型版本、RAG 或场景能力后必须扩展回归集。
