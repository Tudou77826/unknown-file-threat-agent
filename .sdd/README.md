# Software Design Documentation

`.sdd` 是本项目现行软件设计的唯一入口。正式设计描述稳定目标、边界、契约和验收方式；历史交接、旧方案和阶段快照只保存在 `archive/`，不再作为当前实现依据。

## 阅读顺序

1. [softwareArchitecture.md](softwareArchitecture.md)：系统边界、总体架构、关键数据流和演进方向。
2. 对应 Feature 的 `README.md`：Feature 范围、状态和详细文档入口。
3. [shared/system-contracts.md](shared/system-contracts.md)：跨 Feature 数据交换关系。
4. [shared/architecture-decisions.md](shared/architecture-decisions.md)：已经接受的关键架构决策。

## Feature

| 序号 | Feature | 责任 | 当前状态 |
|---:|---|---|---|
| 01 | [data-foundation](features/01-data-foundation/README.md) | 安全数据接入、规范化、存储、查询、Coverage 和数据访问控制 | 已有查询端口与本地适配器；生产数据源待接入 |
| 02 | [judgment-engine](features/02-judgment-engine/README.md) | LLM 驱动的未知文件调查、确定性分析和结论校验 | LangGraph 研判子图已实现 |
| 03 | [response-advisory](features/03-response-advisory/README.md) | 独立的 LLM 处置建议循环和结构化处置方案 | LangGraph 处置建议子图已实现 |
| 04 | [rag-knowledge](features/04-rag-knowledge/README.md) | 调查知识、组织策略和历史案件检索 | 单独规划；本次仅预留接口 |
| 05 | [case-governance](features/05-case-governance/README.md) | 案件生命周期、身份、审批、审计和执行边界 | 父图、Checkpoint 与审批中断已实现；执行集成待建设 |
| 06 | [platform-architecture-migration](features/06-platform-architecture-migration/README.md) | 将现有原型迁移到目标架构、原生 LangGraph 子图和纵向代码边界 | 已完成 |
| 07 | [data-driven-investigation-quality-demo](features/07-data-driven-investigation-quality-demo/README.md) | 用受控数据 Profile 展示数据源对研判与处置质量的决定性影响，并统一外置运行配置 | 已实现并通过 8 条 Profile 路径验收 |

## 文档规则

- `softwareArchitecture.md` 只描述系统级结构和 Feature 关系，不重复 Feature 内部设计。
- 每个 Feature 自主管理需求、设计、模型、策略和验收文档。
- 跨 Feature 的术语、契约和非功能要求放在 `shared/`。
- 现行事实以代码、Cases 和 Tests 为最终依据；文档与实现冲突时必须修正文档或明确标注目标设计。
- 设计文档不得混入 Session 指令、试错记录和临时环境信息。
- 历史文档只允许进入 `archive/`，并保留原文以便追溯。

## 运行时文档

[`investigation_skills/linux-unknown-file/SKILL.md`](../investigation_skills/linux-unknown-file/SKILL.md) 是结构化 LLM Planner 直接读取的运行时资源，不属于普通设计文档，保持原路径。修改它必须同步验证 Planner 和端到端 Case。

## 归档

[archive/README.md](archive/README.md) 记录旧文档的来源、失效原因和新知识去向。归档材料不代表当前架构。
