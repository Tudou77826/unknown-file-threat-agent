# Data Foundation

安全数据底座为研判和处置提供统一、可追溯、受权限控制的数据访问能力。它负责数据，不负责案件结论。

## 文档

- [requirements.md](requirements.md)：目标、范围和验收要求。
- [design.md](design.md)：接入、规范化、存储和查询架构。
- [data-model.md](data-model.md)：规范化事件、实体和 Coverage 模型。
- [verification.md](verification.md)：数据质量、权限和兼容性验收。

## 当前状态

当前已实现 `EvidenceQueryPort`、显式 Scope 查询契约，以及 JSONL/Fixture 本地适配器。它们验证了查询边界和 Coverage 语义，但不构成生产数据底座。
