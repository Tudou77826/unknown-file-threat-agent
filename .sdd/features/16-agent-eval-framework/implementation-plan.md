# Agent Eval Framework Implementation Plan

## 1. 执行结论

实施分为四个连续步骤：先内核后集成——契约与 Runner（含性能门槛测试）先行，打分聚合次之，业务适配器第三，CI 门禁最后。框架全程不 import 业务模块；SecAgent 作为首个消费者以适配器形态接入。每步完成专项测试和全量回归后再进入下一步。

| 步骤 | 交付结果 | 依赖 |
|---:|---|---|
| 01 | `agent_eval` 内核：契约 + Runner + 架构断言 + 假任务性能验证 | 无 |
| 02 | ScoreRunner + Reporter + 两段式离线打分链路 | 01 |
| 03 | SecAgent 适配器 + 运行时收敛裁决报告 + 保留运行时首份基线 | 02 |
| 04 | CI smoke 门禁（仅保留运行时）+ 使用文档 + 抽包清单 | 03 |

本计划不做：LLM-as-judge、沙箱执行、OTel/Langfuse 接入、新案件族扩展。

## 2. 实施步骤

### 01：内核契约与 Runner

目标：定义 Case / RunRecord / EvalTask 三契约与并发执行引擎。

实施内容：

- 新增 `src/threat_agent/agent_eval/`：`core.py`（契约）、`runner.py`（线程池调度、幂等续跑、`--fresh` 重采样语义）；
- 令牌桶限流器（RPM/TPM 双维可配）+ 429 全抖动指数退避；
- 每 worker 独立工作目录与环境夹具复制；产物（transcript/metrics_raw）按 RunRecord 落盘；
- 架构断言：`agent_eval` 不 import 任何 threat_agent 其他子包；
- 用假 EvalTask（受控睡眠模拟 LLM 延迟与 429）完成行为与性能测试。

验证门槛：

- 假任务下并发加速比 ≥ 线程数 × 0.8；限流配置生效（超发次数为 0）；kill -9 后重跑仅补未完成 run；
- 同参数重跑默认命中已完成项，传 fresh 参数时全部重采样；
- 存量全量测试通过。

### 02：ScoreRunner 与 Reporter

目标：两段式的第二段——对落盘产物离线打分并聚合成报告。

实施内容：

- `scoring.py`：Scorer 协议、Score 模型、按套件批量打分的 ScoreRunner（输入为 RunRecord 目录，无任何 LLM/网络调用）;
- `report.py`：聚合矩阵（suite × config × tag 切分）、verdict 分级混淆矩阵、pass^k 统计（epoch 维度归约）、回归对比（同 suite 跨版本基线 diff）；输出 JSON + Markdown；
- 失败运行（error/timeout）在报告中单列且不计入通过率分母的说明口径。

验证门槛：

- 对手造 RunRecord 集：各指标数值可与手工核算一致；删除缓存重打分零网络调用、秒级完成；
- pass^k 在 k=3 样例上归约逻辑正确（部分通过不被计为过）。

### 03：SecAgent 适配器、运行时收敛裁决与首份基线

目标：框架接入真实业务执行路径；以一次性成对实验裁决 graph/middleware 去留，并对保留运行时出具常规基线。

实施内容：

- `bootstrap/eval_cli.py` 与 `adapters/eval_tasks.py`：CaseFactory 从合成数据生成器枚举 C2 两族 × L0–L3；TaskAdapter 按案例复制活动库、经真实 gateway/boundary/report 流水线运行（运行时归属仅作为 config 参数传入）；
- 五个确定性 Scorer：VerdictMatch、PublicationStatus、DegradationCorrectness、BoundaryInterception、CostEfficiency（复用业务侧校验器与账本字段）；
- 对抗标签小集：告警 payload 注入越界诱导字段（跨主机 host_refs 等），验证拦截与纠正行为被记为独立案例而不是脏数据；
- **裁决实验（一次性）**：8 案例 × L0–L3 × k=3 × 两运行时成对全量比较，产出带明确去留建议的裁决报告——数据项包括 verdict 一致性、接地发布率、正确降级率、越界拦截率与单案成本，结论回填 Feature 15 的挂起切换决策；
- 裁决落实后：仅对保留运行时重新出具基线报告；另一运行时退出被测集（demo 选择器收窄由业务侧另行执行）。

验证门槛：

- 裁决实验 48 runs 全部有终态记录（含可能的模型错误失败，如实呈现）；
- 裁决报告包含明确的单一保留建议及依据数字；
- 保留运行时基线按单运行时口径出具；
- 单案件失败不影响整体跑批（隔离验证）；存量全量测试通过。

### 04：CI 门禁与抽包准备

目标：评测进入日常流程，框架具备脱离本仓库的条件。

实施内容：

- smoke 子集标记（每族取代表案例，≤12 个，仅覆盖裁决保留的运行时）与 CI 脚本；门禁阈值写进 CI 配置并在报告头部声明；
- 使用文档：其他项目接入只需要实现 EvalTask + 定义 Scorer 的最小说明（一个完整示例项目视角）；
- 抽包清单：package 化命名、依赖声明、导出接口清单（只列不动）。

验证门槛：

- CI 上手动触发 smoke 运行 ≤ 5 分钟出报告；
- 文档中的最小示例可以脱离 SecAgent 数据独立成立（用假 TaskAdapter 演示）。
