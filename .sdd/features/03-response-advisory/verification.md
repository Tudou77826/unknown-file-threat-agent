# Response Advisory Verification

- 相同 Verdict 在不同资产关键度下产生不同的审批和影响结果。
- 政策冲突时选择更严格的有效政策并报告冲突。
- 过期、越权或无来源的 RAG 文档不能支撑动作。
- 缺少目标实体、回滚或验证步骤的高风险动作被 Validator 拒绝。
- 处置 LLM 不能修改 JudgmentResult。
- 使用模拟执行器验证幂等、部分成功、失败和回滚，不连接真实生产动作作为首期验收。
