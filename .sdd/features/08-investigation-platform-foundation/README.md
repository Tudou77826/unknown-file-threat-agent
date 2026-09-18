# Investigation Platform Foundation

本 Feature 将当前参考实现推进为可接收客户测试数据的未知文件调查平台最小闭环。范围包括安全活动模型与数据接入底座、正式调查报告、持久化运行与审计、最小调查运行接口。

## 状态

实施中。需求、设计和实施计划已完成评审。

## 文档

- [requirements.md](requirements.md)：产品目标、范围和验收条件。
- [design.md](design.md)：数据语义、组件边界、关键契约和迁移设计。
- [implementation-plan.md](implementation-plan.md)：分步落地、首版收敛和验证门槛。

实施步骤 01—07 已完成。在线研判使用四个数据能力工具和正式报告发布校验；运行、事件、审计和发布产物可在服务重启后查询，但这不代表运行中任务能够续跑。展示页面通过正式调查 API 读取运行事件、`InvestigationReport` 和独立的 `ResponsePlan`，不再按预置数据集补写结论。首版使用 SQLite 完成业务闭环并保持存储可替换边界；百万级活动仅作为索引、分页和批量写入的设计假设，不在本 Feature 做容量实测。当前暂缓的生产化缺口见 [design.md](design.md)。确定性路径只承担离线测试，不构成版本兼容承诺。
