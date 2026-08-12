# Archive Index

本目录保存迁移前的原始文档和设计资产。归档材料用于追溯历史，不代表当前架构；当前设计从 [../README.md](../README.md) 进入。

## 归档分类

- `handoffs/`：Session 和项目上下文交接，包含需求演进、阶段结论和当时的下一步。
- `legacy-docs/`：迁移前完整 `docs/` 目录，包括旧方案、实现快照、字段映射、方法论和视觉资产。

## 知识迁移关系

| 旧知识 | 新位置 |
|---|---|
| 端到端方案与总体边界 | `../softwareArchitecture.md` |
| 证据采集和场景数据需求 | `../features/01-data-foundation/` |
| Agent、Tool、Evidence 和 Verdict 设计 | `../features/02-judgment-engine/` |
| 未知文件攻击路径方法 | `../features/02-judgment-engine/scenarios/` 和运行时 Skill |
| 处置建议设想 | `../features/03-response-advisory/` |
| 历史检索设想 | `../features/04-rag-knowledge/` |
| Scope、审批和运行控制 | `../features/05-case-governance/` |
| 公共术语与跨模块契约 | `../shared/` |

## 已知失效内容

归档材料中提到的 `run_agent.py`、`skills/`、`examples/`、`schemas/` 和 `legacy_mvp/` 当前不存在；早期固定 JSON、简单证据打分和固定 Skill 链也不是现行实现。引用归档内容时必须重新核对当前代码、Cases 和 Tests。

## 保留策略

归档文件保持原文，不进行静默改写。确认某份历史材料不再具有审计、需求或设计价值之前，不直接删除。
