# RAG Knowledge

RAG Knowledge 为研判和处置建议提供受权限、版本和来源约束的知识检索。它与安全遥测查询分离。

## 文档

- [requirements.md](requirements.md)
- [design.md](design.md)
- [knowledge-model.md](knowledge-model.md)
- [retrieval-policy.md](retrieval-policy.md)
- [verification.md](verification.md)

## 价值优先级

1. 组织处置 SOP、审批、业务约束和回滚手册。
2. 调查方法、产品文档和威胁知识。
3. 经质量控制的历史案件和复盘。

当前项目未实现 RAG。本次平台架构迁移只预留查询契约、调用边界和 Null Adapter；知识来源、索引、检索与评测后续作为独立需求审批和实施。
