# Data-Driven Investigation Quality Demo Verification

## 1. 对照实验

- 校验同一基础案件的四个 Profile 使用完全相同的告警摘要和引擎版本。
- 校验 Profile 之间只有数据可见性、Coverage 和资产上下文差异。
- 恶意与合法案件分别运行 L0 至 L3，并保存结构化差异结果。
- 校验 L3 恶意案件形成证据化攻击链，L3 合法案件能够引用反证降低误报。

## 2. 数据可信性

- 每个 Fact、Finding 和 Relation 的 Evidence ID 均可在参考存储中解析。
- `available`、`partial`、`empty` 和 `unavailable` 的返回语义分别测试。
- Profile 与底层数据不一致时必须失败，不能静默降级。
- `DataReadinessReport` 的受阻问题与 Evidence Role、Coverage 一致。

## 3. 配置

- 使用仅包含安全示例值的 `.env.example` 完成离线确定性运行。
- 分别验证 `.env`、进程环境变量和 CLI 参数的覆盖优先级。
- 缺失 LLM 凭据、非法预算、错误路径、冲突 Backend 和无效 Profile 均在启动阶段失败。
- 扫描业务模块，确保只有 `bootstrap` 读取环境变量。
- 扫描代码中的部署参数，确保不存在与配置对象重复的硬编码默认值。
- 校验日志、异常和报告不泄漏 API Key。

## 4. 回归与展示

- 全量自动化测试和 18 个黄金 Case 不退化。
- Checkpoint 中断恢复、双循环、RAG Null Adapter 和架构依赖测试继续通过。
- 展示页可以并排查看 L0 至 L3 的 Coverage、可回答问题、结论、反证和处置差异。
- 页面和报告明确标注参考数据范围，不包含生产效果声明。

## 5. 业务验收口径

验收结论只包括：数据能力与可回答问题之间的映射、完整数据对攻击确认和误报排除的作用、以及生产接入需要补齐的数据清单。不输出生产准确率、召回率或节省工时承诺。

## 6. 已验证结果

| 数据集 | L0 | L1 | L2 | L3 |
|---|---|---|---|---|
| C2 恶意参考样本 | `insufficient_evidence` | `insufficient_evidence` | `confirmed_malicious` | `confirmed_malicious` |
| 合法运维参考样本 | `insufficient_evidence` | `insufficient_evidence` | `likely_malicious` | `benign` |
| 可回答问题数 | 0 | 2 | 4 | 5 |

自动化测试覆盖两个数据集的 8 条确定性 Profile 路径、配置优先级、Profile 版本拒绝、Readiness 单调性、相同研判下的资产差异化处置、AI 运行接口、API 和 HTML 转义。在线模型另执行 L3 合法样本冒烟验证：研判模型完成多轮工具选择，处置模型完成结构化建议，最终输出 `benign`。
