# Data-Driven Investigation Quality Demo

本 Feature 建设一套可重复的参考数据底座和对照演示，用同一告警、同一引擎和不同数据源 Coverage，展示数据源如何决定研判质量上限。同时将部署与运行配置统一收口到项目根目录 `.env`。

## 状态

已实现并通过验收。当前提供两个版本化参考数据集、L0～L3 四级 Data Profile、SQLite 参考数据存储、Data Readiness、资产感知处置建议、对照 API 和展示页。页面同时保留确定性对照基线，并允许用户触发真实双 LLM 运行，观察研判规划、数据查询、证据返回、结论和处置建议过程。RAG 继续使用 Null Adapter。

## 文档

- [requirements.md](requirements.md)：范围、约束和验收条件。
- [design.md](design.md)：对照实验、参考数据底座和展示设计。
- [configuration.md](configuration.md)：根目录 `.env` 的配置边界与配置项。
- [implementation-plan.md](implementation-plan.md)：实施批次、依赖顺序和验证门槛。
- [verification.md](verification.md)：验收方法和业务展示口径。

## 业务结论

Demo 不证明生产环境准确率。它证明数据完整性同时决定攻击确认能力和误报排除能力，并把生产数据底座需要提供的数据能力转换为可检查清单。

当前参考结果：恶意样本在 L2 获得行为证据后由 `insufficient_evidence` 进入 `confirmed_malicious`；合法运维样本在 L2 因缺少反证仍为 `likely_malicious`，L3 加入软件来源和批准端点后降为 `benign`。
