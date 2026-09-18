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

测试数量不是该 Feature 的静态契约。当前回归基线应由 `uv run pytest -q` 和
`uv run pytest --collect-only` 实时取得，其中包含模块依赖方向和参考数据
Profile 检查；新增数据模型、模型版本、RAG 或场景能力后必须扩展回归集。
