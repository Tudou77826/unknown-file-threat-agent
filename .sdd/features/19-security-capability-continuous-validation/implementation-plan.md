# 安全能力持续仿真与 AI 研判评测 — Implementation Plan

## 1. 执行结论

PoC 不追求全量平台能力，先打通「Case → Replay → 规则检测 → AI 研判 → 评分 → 报表」最小闭环，再补 AI 自主攻击环境。

| 步骤 | 交付结果 | 依赖 |
|---:|---|---|
| 01 | Case 与 Replay 数据契约及存储 | 无 |
| 02 | 10～20 个标准 ATT&CK Case 与参数化 | 01 |
| 03 | 态势感知规则结果与 AI 结果采集 | 01、02 |
| 04 | Scorer 与基础统计报表 | 03 |
| 05 | AI 自主攻击环境与 Candidate Case 沉淀 | 03 |

本计划不做：自动阻断、生产在线监控、真实攻击 Agent 的实现。

## 2. 实施步骤

### 01：Case 与 Replay 契约

目标：定义标准化 Test Case 与 Replay Dataset 的结构与存储。

实施内容：

- 定义 Case Schema（design.md §3.1 字段）与 Replay Dataset 目录约定；
- 落地存储与版本化（进 git 或对象存储）；
- 支持 Case 参数化派生。

验证门槛：

- 一个手写 Case + Replay 可被完整加载；
- 参数化派生出的变体共享 Ground Truth 且字段完整。

### 02：标准 ATT&CK Case

目标：用 Atomic / CALDERA / Adversary Emulation 产出可重复 Case。

实施内容：

- 选取 10～20 个 ATT&CK Technique 覆盖代表场景；
- 攻击首次运行并采集文件与遥测，落为 Replay；
- 建立规则与 AI 的预期结果。

验证门槛：

- 每个 Case 有明确 ATT&CK 标签与 Ground Truth；
- Replay 重放结果稳定。

### 03：结果采集

目标：从被测安全系统采集规则与 AI 两侧结果。

实施内容：

- 规则侧：对接外部态势感知系统，采集命中 / 未命中与告警内容并对应到 Case，告警格式差异在采集适配器内收敛；
- AI 侧：记录研判结论、证据、风险等级与处置建议；
- 统一落到 Case 结构下。

验证门槛：

- 同一 Case 可采集到规则与 AI 两条结果记录；
- 规则命中与未命中路径均有样本。

### 04：Scorer 与报表

目标：基于 Ground Truth 打分并出基础统计。

实施内容：

- 规则评分器：检出率、漏检率、误报率、ATT&CK Coverage、Regression；
- AI 评分器：补漏率、判断 / 证据 / 风险 / 处置正确率、稳定性、耗时与成本；
- 整体指标与基础统计报表。

验证门槛：

- 报表同时给出规则、AI 与整体三类指标；
- 指标可由 Case 明细手工复核。

### 05：AI 自主攻击环境

目标：搭建自主攻击靶场并沉淀 Candidate Case。

实施内容：

- 部署授权靶场与 AI Pentest Agent（目标环境、授权边界、攻击目标、可用工具）；
- 运行自主攻击并采集有效结果；
- 将有效结果沉淀为 Candidate Case，人工确认后进入回归集。

验证门槛：

- 自主攻击在授权边界内运行；
- 至少产出一个经确认的 Candidate Case。

## 3. PoC 结论产出

PoC 结束时给出：

1. 标准攻击下确定性规则的覆盖率；
2. 非固定自主攻击下规则的覆盖率；
3. 规则漏检后的 AI 补漏率。
