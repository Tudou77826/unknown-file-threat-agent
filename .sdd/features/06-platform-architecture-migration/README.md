# Platform Architecture Migration

本 Feature 定义如何把当前未知文件研判原型迁移到“数据底座、双 LLM 循环、RAG、输出展示”架构，并由 LangGraph 接管流程控制。

## 状态

迁移已完成。RAG 按批准范围仅保留接口与 Null Adapter，具体实现后置。

## 文档

- [requirements.md](requirements.md)：目标、范围与验收条件。
- [design.md](design.md)：目标架构、LangGraph 工作流和渐进迁移方案。
- [implementation-plan.md](implementation-plan.md)：实施步骤、验证门槛与回滚点。

## 与其他 Feature 的关系

本 Feature 负责跨模块迁移与集成，不重新定义各能力内部规则。各领域设计仍由以下 Feature 维护：

- [Data Foundation](../01-data-foundation/README.md)
- [Judgment Engine](../02-judgment-engine/README.md)
- [Response Advisory](../03-response-advisory/README.md)
- [RAG Knowledge](../04-rag-knowledge/README.md)
- [Case Governance](../05-case-governance/README.md)
