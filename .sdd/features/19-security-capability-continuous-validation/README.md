# 安全能力持续仿真与 AI 研判评测

用标准攻击、完整攻击链和 AI 自主攻击持续产生带 Ground Truth 的测试数据，量化确定性规则的检出质量、规则漏检后暴露的未知文件规模、AI 对未知文件的补漏与研判质量，以及整体安全感知能力随版本迭代的提升或退化。

定位是**感知、研判与持续评测**：本系统不承担自动阻断，也不替代 EDR / SIEM 的检测与响应能力。

本 Feature 站在被测安全系统之外，把确定性规则系统、AI 研判 Agent（本项目）、OpenAEV 与 AI 自主攻击 Agent 统一编排为「攻击 → Case → Replay → 检测 → 研判 → 评分 → 回归」闭环。

## 与其他 Feature 的关系

| 关联 | 关系 |
|---|---|
| 16 agent-eval-framework | 复用其 Dataset / 运行 / 打分三件套与两段式产物打分，作为 AI 侧的评测执行内核；本 Feature 不重复实现调度与并发 |
| 18 attack-knowledge-corpus | ATT&CK 语料与 T-ID 通道作为攻击行为坐标系和 Case 标签来源 |
| 02 judgment-engine / 03 response-advisory | 被测的 AI 研判与处置建议链路；本 Feature 只采集其输出并评分，不修改其行为 |
| 05 case-governance | 不涉及。本 Feature 的 Test Case 与案件治理中的 InitialCase 无关，不复用案件身份与生命周期 |

## 文档

- [requirements.md](requirements.md)：目标、范围边界、功能与非功能要求、验收条件。
- [design.md](design.md)：总体架构、Case 与 Replay 模型、被测链路、评分体系、OpenAEV 集成边界、运行模式。
- [implementation-plan.md](implementation-plan.md)：PoC 分步实施与验证门槛。

## 状态

需求已登记（2026-09-21）。设计已审批（2026-09-29）并完成评审修订：规则侧对接外部态势感知系统（攻击运行期采集结果，不建注入通道），技术选择限定 Linux + 落文件 + 单主机，补充良性基线与漏检受理回执口径。尚未实现。
