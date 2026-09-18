# Agent Eval Framework

搭建公司内可跨项目复用的 Agent 评测框架：框架本体负责调度、并发、限流、产物持久化、打分聚合与分层套件；各业务项目只需提供「如何运行一个案例」的适配器和项目专属打分器。

设计定位是对齐业界事实标准的正交切分（Dataset / 运行 / 打分三件套），与本仓库已有的 `agent_middleware` 抽包先例共用同一套「协议进包、语义在业务侧」的原则。

关于原有 graph/middleware 双运行时：它不是常设被测维度。正式调查已经收敛到 create_agent + middleware；评测、CI 与 Demo 均只验证这一条路径。评测框架不重新引入运行时 A/B 选择。

## 文档

- [design.md](design.md)：背景、开源选型结论、总体方案、自研/复用边界、性能预算。
- [implementation-plan.md](implementation-plan.md)：四个实施步骤与验证门槛。

## 状态

实施中（2026-09-18）：

- **步骤 01 完成**：`agent_eval` 内核（`core.py` 契约 / `runner.py` 并发引擎 / `rate_limit.py` 双维令牌桶）。
  幂等续跑（仅跳过 ok，error/timeout 补跑）、`fresh` 重采样、单案失败隔离、并发加速比门槛全部有测试
  （`tests/test_agent_eval_kernel.py` 14 例）；架构门禁：agent_eval 不 import 任何 threat_agent 其他子包
  （含 shared——本地 `_base.py` 镜像 StrictModel，与 agent_middleware 同一抽包纪律）。
- **步骤 02 完成**：`scoring.py`（ScoreRunner + 多维 Score + regrade 落盘）与 `reporter.py`
  （聚合矩阵 / pass^k 归约 / 回归 diff / Markdown 渲染）。
- Harbor 吸收结论见 design.md §9（考题目录约定、named reward dimensions、regrade、suite@version
  版本钉住、milestone 评分、参考解为出题必备件）。
- **待办（步骤 03/04）**：SecAgent 适配器（CaseFactory + TaskAdapter over RunService）、五个确定性
  Scorer、首份基线报告；CI smoke 门禁。运行时收敛裁决实验已无对象（graph 运行时已退役，middleware
  为唯一运行路径），步骤 03 相应缩减为"适配器 + 基线"。
