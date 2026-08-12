# Data-Driven Investigation Quality Demo Implementation Plan

> 状态：8 个实施步骤已全部完成，实际验收结果见 [verification.md](verification.md)。

## 1. 执行原则

实施分为八个连续步骤。每一步必须保持主分支可运行，并在专项测试和全量回归通过后进入下一步。实际 `.env` 可能包含本地凭据，实施时只新增配置键和 `.env.example`，不得覆盖、提交或输出现有 `.env` 内容。

| 步骤 | 交付结果 | 依赖 |
|---:|---|---|
| 01 | 类型化配置与根目录 `.env` 收口 | 无 |
| 02 | Demo 跨模块契约与数据模型 | 01 |
| 03 | SQLite 参考数据存储与导入 | 02 |
| 04 | L0～L3 Data Profile 与对照数据集 | 03 |
| 05 | 确定性 Data Readiness Evaluator | 04 |
| 06 | 参考资产目录与 ResponseContext Adapter | 04 |
| 07 | 对照运行编排、读模型和展示页 | 05、06 |
| 08 | 全量验收、演示脚本和文档收敛 | 07 |

## 2. 实施步骤

### 01：类型化配置与 `.env` 收口

目标是让 `bootstrap` 成为唯一配置入口。

- 引入类型化 `AppSettings`，按应用、模型、预算、图运行、数据、Checkpoint、展示和日志拆分子配置；
- 加载优先级实现为 CLI、进程环境变量、根目录 `.env`、类型化默认值；
- 迁移模型参数、CLI 默认值、双循环预算、递归上限、查询上限、Checkpoint 和输出路径；
- 更新 PowerShell/Shell 启动脚本并新增无凭据 `.env.example`；
- 保留旧模型变量的短期兼容告警，不允许业务模块直接读取环境变量。

验证门槛：配置优先级、类型校验、确定性模式无凭据运行、LLM 模式缺失凭据失败、密钥不进入日志；全量测试通过。

### 02：Demo 契约与数据模型

目标是先稳定跨模块结构，再建设存储和展示。

- 定义 `DataProfile`、`SourceCoverageRule`、`DataReadinessReport` 和对照结果契约；
- 定义参考数据集版本、生成元数据和资产上下文结构；
- 明确 `available`、`partial`、`empty`、`unavailable` 的序列化语义；
- 为契约增加 JSON 往返、版本拒绝和非法组合测试。

验证门槛：契约不依赖业务模块；Profile 不包含期望 Verdict；所有契约可稳定序列化。

### 03：SQLite 参考数据存储与导入

目标是让 Agent 通过真实存储边界查询，而不是读取 Case 目录。

- 在数据底座实现 SQLite Schema、初始化和版本检查；
- 存储告警、Evidence、Entity、Relation、Coverage、资产上下文和数据集元数据；
- 实现参考数据导入器及幂等导入键；
- 实现基于现有 `EvidenceQueryPort` 的 SQLite Adapter；
- 保留 JSONL/Fixture Adapter，用契约测试保证查询语义一致。

验证门槛：重复导入不产生重复记录；Scope、时间、类型和数量限制有效；Evidence 可追溯到原始记录标识。

### 04：Data Profile 与对照数据集

目标是建立只改变数据可见性的受控实验。

- 建立恶意 C2 和合法运维两份完整参考数据集；
- 为每份数据集定义 L0、L1、L2、L3 Profile；
- 实现 Profile-aware Adapter，在查询边界应用数据源可见性和 Coverage；
- 校验四个 Profile 的告警摘要、引擎版本、工具目录和预算完全一致；
- 记录固定随机种子和数据集版本。

验证门槛：Profile 不能修改 Evidence 内容或携带期望结果；同版本重复生成的数据摘要一致；Profile 与存储不一致时显式失败。

### 05：Data Readiness Evaluator

目标是确定性说明数据能力解锁了哪些调查问题。

- 将 Evidence Role、场景要求和数据源能力建立版本化映射；
- 根据实际 Coverage 计算可回答问题、受阻问题和建议补充能力；
- 将 `DataReadinessReport` 接入案件发布流程；
- 保证 Evaluator 不修改 Verdict、不接受 Knowledge ID 作为 Evidence。

验证门槛：L0～L3 报告随数据能力单调增加可回答问题；恶意程度不要求单调增加；所有结论可追溯到 Role 和 Coverage。

### 06：参考 ResponseContext Adapter

目标是展示资产数据如何改变处置质量而不改变研判事实。

- 建立非生产参考资产目录；
- 实现读取参考 SQLite 资产表的 `ResponseContextPort` Adapter；
- 注入资产重要性、负责人、维护窗口、隔离策略和业务影响；
- 对缺失字段输出 `missing_context`，不使用硬编码补齐。

验证门槛：相同 `JudgmentResult` 在生产关键资产和测试资产上产生不同处置约束；研判事实保持完全一致。

### 07：对照运行与展示

目标是一次运行生成同一案件 L0～L3 的可比较结果。

- 增加 Demo 运行用例，固定引擎配置后依次执行四个 Profile；
- 发布包含 Data Readiness、Judgment、Response 和 Coverage 差异的对照读模型；
- 扩展只读 API 和服务端页面；
- 展示固定条件、数据矩阵、可回答问题、新增事实、反证、攻击路径和处置差异；
- 页面和报告固定标注参考数据边界。

验证门槛：恶意与合法两套对照均可离线完成；页面不读取内部图状态或参考数据库；HTML 转义和空状态测试通过。

### 08：验收与交付收敛

目标是形成可重复演示和可推动数据底座建设的交付物。

- 提供一条命令初始化参考数据并运行两组 L0～L3 对照；
- 输出数据能力矩阵、Data Readiness 报告和案件对照结果；
- 运行全量单元、契约、架构、Checkpoint 和端到端测试；
- 更新 README、软件架构、Feature 状态和运行说明；
- 检查仓库不包含 `.env`、凭据、运行数据库和输出文件。

验证门槛：现有 18 个黄金 Case 不退化；新增两组八条 Profile 路径全部通过；离线 Demo 不依赖模型、RAG 或外部数据源。

## 3. 代码落点

| 能力 | 主要位置 |
|---|---|
| 配置 | `src/threat_agent/bootstrap/`、根目录 `.env.example` |
| Demo 契约 | `src/threat_agent/contracts/` |
| 参考存储与 Profile Adapter | `src/threat_agent/data_foundation/` |
| Data Readiness | `src/threat_agent/case_management/` |
| 参考资产上下文 | `src/threat_agent/response_advisory/adapters/` |
| 对照读模型与页面 | `src/threat_agent/presentation/` |
| 参考数据资产 | 根目录 `demo_data/` |
| 自动化验证 | `tests/` |

不新增跨领域 `demo` 业务包。每项能力归入其所属模块，根目录 `demo_data/` 只保存非代码参考资产。

## 4. 整体验收

- 数据 Profile 是实验中的唯一数据变量；
- 恶意样本证明完整数据支持攻击确认，合法样本证明完整反证降低误报；
- `DataReadinessReport` 能把缺失数据源映射到受阻问题；
- 处置建议能够使用资产和业务上下文；
- 所有可变运行参数由统一配置对象提供，业务模块不读取环境变量；
- `.env.example` 可运行离线 Demo，实际 `.env` 和凭据不进入 Git；
- RAG 继续保持 Null Adapter，生产效果声明仍属于非目标。
