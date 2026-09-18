# Agent Middleware Foundation — Current Verification

## 1. 正式路径

在线调查只使用 MiddlewareJudgmentRunner：

- 通过 create_agent 注册受控调查工具；
- 预算、官方摘要、领域降采样与边界防护按既定顺序挂载；
- CaseGraph 继续负责案件生命周期、报告后的处置建议和审批中断；
- 报告发布仍走同一接地校验、受限重判与兜底流水线。

## 2. 已锁定行为

| 行为 | 自动化验证 |
|---|---|
| middleware 包不依赖任何安全业务模块 | test_architecture_dependencies.py::test_agent_middleware_is_self_contained |
| 组件边界、预算与压缩协议 | test_agent_middleware_boundary.py、test_agent_middleware_budget.py、test_agent_middleware_compaction.py |
| 正常完成、预算降级、边界拒绝与报告兜底 | test_middleware_demo_runtime.py |
| API 只启动正式路径，旧 runtime 字段被拒绝 | test_middleware_demo_runtime.py |
| 网关只消费聚合数据 Port | test_architecture_dependencies.py::test_judgment_gateway_consumes_the_aggregate_data_port_only |
| 数据 Profile 在时间线、原始记录和指标输入中一致生效 | test_llm_investigation_tools.py::test_aggregate_data_port_applies_profile_visibility_to_all_reads |

## 3. 已退出的验证资产

图路径与 middleware 路径的双跑脚本、页面选择器和 API runtime 参数已删除。它们解决的是迁移期间的对拍问题，不再构成长期产品能力或 CI 维度。

## 4. 验证边界

自动化测试覆盖框架组装、类型契约和受控脚本模型路径；它不证明真实模型的成本、时延或研判质量，也不证明中断任务恢复、身份授权或敏感事件展示能力。后者仍按 Feature 08 的生产化缺口处理。
