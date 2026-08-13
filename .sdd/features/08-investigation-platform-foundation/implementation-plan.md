# Investigation Platform Foundation Implementation Plan

## 1. 执行结论

实施分为七个连续步骤。数据模型先于存储和接入，存储与查询先于 LLM 报告，正式报告先于页面切换。每一步完成专项测试和全量回归后再进入下一步。项目尚未发布首版，不承担历史版本升级兼容；开发期旧路径只在新链路尚未覆盖相应能力时短暂存在，并在第 07 步直接清理。

| 步骤 | 交付结果 | 依赖 |
|---:|---|---|
| 01 | 数据语义契约与首版边界 | 无（已完成） |
| 02 | 原始记录、规范化活动与批量接入 | 01（已完成） |
| 03 | 实体关系、活动查询与 EvidenceReference | 02（已完成） |
| 04 | 数据能力工具驱动的 LLM 调查与报告 | 03（已完成） |
| 05 | 持久化运行、可观测事件与审计 | 04（已完成） |
| 06 | 最小调查运行接口与展示迁移 | 05（已完成） |
| 07 | 首版架构收敛与容量方案取舍 | 06（已完成） |

本计划不建设完整 Connector 平台、用户与租户权限系统、案件 CRUD、人工审批中心、通用任务队列、RAG 或生产处置执行。

## 2. 实施步骤

### 01：数据语义契约与首版边界

目标是先稳定 RawRecord、Activity、实体关系、案件 Evidence 和调查报告之间的语义，暂不修改现有运行结果。

实施内容：

- 在 `contracts` 中定义 `RawRecordEnvelope`、活动公共信封和七类首期活动契约；
- 定义 `EntityIdentity`、`ObservedRelation`、`EvidenceReference`、`ActivityQueryResult`、查询接口定义和执行边界；
- 定义 `InvestigationReport`、`InvestigationRun`、`OperationalEvent` 和 `AuditEvent`；
- 为所有新契约增加 Schema 版本、JSON 往返和非法组合校验；
- 定义 Activity/EvidenceReference 的首版语义边界，并验证其与案件 Evidence 的引用关系；
- 更新共享术语和跨 Feature 契约，明确 Activity 是全局事实，Evidence 是案件引用。

验证门槛：

- 新契约不依赖业务 Feature；
- 同一 Activity 可生成两个不同案件的 EvidenceReference，底层对象不含 `case_id`；
- 扩展活动缺少来源、时间、主体或原始引用时校验失败；
- 现有 120 项测试全部通过。

阶段边界：本步骤只建立契约，不切换默认运行路径。

### 02：原始记录、规范化活动与批量接入

目标是形成“原始数据可追溯、持久化前完成规范化”的最小数据接入闭环。

实施内容：

- 在 `data_foundation` 中定义原始记录存储、活动写入和 Parser 端口；
- 实现首期 SQLite 存储，将原始记录、规范化活动、接入批次和隔离记录分表保存；
- 为租户、活动域、事件时间、主机、实体关联键和来源记录 ID 建立必要索引；
- 实现 Dataset Manifest 和 JSONL 批量导入用例，使用来源记录 ID 与内容摘要保证幂等；
- 实现两种来源 Parser：当前参考 JSONL 和一份字段结构不同的厂商风格样例，至少共同输出 Process、Network、File 三个活动域；
- 将 Socket、Service、Package 和 Asset 规范化纳入参考数据迁移；
- 导入失败记录进入隔离区，接入报告明确成功、失败、重复、字段缺失和实际时间范围；
- 保留原始 Payload 的受管引用，不向领域层暴露文件路径或数据库 BLOB。

验证门槛：

- 两种来源格式经不同 Parser 产生等价的规范化活动语义；
- 重复导入不产生重复 RawRecord 或 Activity；
- Parser 版本、原始记录和规范化活动可以相互追溯；
- 导入报告准确记录成功、重复、失败、时间范围和实际活动域，不生成质量等级；
- 参考数据能够从新接入链路重新构建且摘要稳定；
- 全量测试通过。

回滚点：现有 `SQLiteReferenceDataStore` 继续服务 Demo，新存储尚未成为查询默认路径。

### 03：实体关系、活动查询与 EvidenceReference

目标是让调查工具查询规范化活动，而不是查询预先绑定案件的 Evidence。

实施内容：

- 实现 Host、File、Process、User、NetworkEndpoint、Package、Service 和 BusinessAsset 的实体索引；
- 实现确定性实体解析，Process 使用主机、PID 和进程开始时间，其他实体保留来源别名和有效时间；
- 将确定关系和候选关系分开保存，关系始终引用支撑 Activity；
- 实现按活动域划分的强类型查询端口，共享 `AccessContext`、Scope、时间和分页；
- SQLite Adapter 负责查询翻译、实体关联、接口定义和实际执行边界记录；
- 查询结果按案件和运行生成轻量 `EvidenceReference`；
- 为离线确定性测试提供 ActivityQueryResult 到 EvidenceBundle 的测试投影；该投影不进入在线 LLM 路径；
- 迁移参考 Demo 到新查询路径，旧 `evidence.case_id` 表仅作为短期回归来源。

验证门槛：

- 相同 PID 不同生命周期不会被合并为同一 Process；
- 候选关系不能通过 Fact/Finding 的确认关系校验；
- 同一 Activity 可被多个案件引用且不复制底层活动；
- 空结果、分页、Scope 收缩和接口约束均有契约测试；
- 现有黄金 Case 的事实、Finding 和证据引用语义不退化；
- 存储 Adapter 可由内存 Fake 替换，研判代码不包含 SQL；
- 全量测试通过。

阶段边界：在线 LLM 调查完成切换前，离线确定性测试仍保留独立投影。

### 04：数据能力工具驱动的 LLM 调查与报告

目标是用稳定的四工具目录驱动 LLM 调查，再让 LLM 读取接口定义、实际执行边界和已验证事实，自行判断数据是否支持结论并形成正式中文调查报告。

实施内容：

- 定义 `query_activities`、`explore_entity`、`get_raw_records` 和 `calculate_activity_metrics` 四个 LLM 数据工具及其结构化输入输出；
- 使用 `StructuredTool`、`bind_tools`、`AIMessage.tool_calls` 和 `ToolMessage` 承载在线工具协议，LangGraph 保持流程控制；
- 实现 Tool Gateway，由运行上下文注入租户、案件、运行和授权 Scope，并路由到活动查询、实体投影、原始记录和确定性计算端口；
- 将 `request_scope_expansion` 和 `finish_investigation` 保持为 LangGraph 流程动作，不注册为数据工具；
- 新调查 Planner 只选择四个数据工具或两个流程动作，不直接使用按攻击场景命名的旧工具；
- 在研判子图末端增加报告上下文构建、LLM 报告生成、发布校验和修复节点；
- 报告上下文只包含可引用的 Activity/EvidenceReference、Fact、Finding、候选解释、接口定义和查询执行边界；
- Prompt 明确要求模型检查字段、关联键、时间、Scope、分页和返回记录，不预先给出数据质量结论；
- LLM 生成威胁结论、攻击现状、影响范围、攻击链、反证、未解决问题和数据限制；
- 发布校验检查引用存在性、实际 Scope 和候选关系；
- 校验失败进入有限次数修复，耗尽后发布受限或证据不足报告；
- `JudgmentResult` 继续作为处置循环的稳定输入，由已发布报告和验证后的事实投影生成；
- 增加确定性 Fake Report Composer，离线 CI 不依赖在线模型。

验证门槛：

- 四个工具的参数、运行上下文注入、Scope 越界、分页和返回契约均有测试；
- 原始记录工具拒绝未被本次运行查询结果引用的记录；
- 确定性计算工具只返回客观计算，不给出攻击场景或 Verdict；
- 报告不能引用未知对象、越出主机/时间 Scope 或把候选关系写成事实；
- LLM 能根据不同的接口字段、查询范围、分页和返回结果说明自己的判断依据与限制；
- 在线模型冒烟输出简体中文报告，离线 Fake 路径覆盖修复和预算耗尽；
- ResponseGraph 只消费发布后的 `JudgmentResult`；
- 全量测试通过。

回滚点：父图继续发布现有确定性 JudgmentResult，正式报告节点可通过组合配置关闭。

### 05：持久化运行、可观测事件与审计

目标是替换 Demo `_jobs` 内存事实源，使运行过程和关键决策在服务重启后仍可查询。

实施内容：

- 定义 InvestigationRun、OperationalEvent、AuditEvent 和报告结果的存储端口；
- 实现首期 SQLite 持久化 Adapter，并与安全活动表保持逻辑隔离；
- 将 DemoRunService 改为 PersistentRunService，启动、阶段、完成和失败状态写入运行库；
- 图节点、模型调用、工具查询、校验修复和结果发布写入结构化运行事件；
- 模型事件记录供应商、模型、Prompt 版本、耗时、Token、重试和错误类型，不记录 API Key；
- 审计事件记录运行来源、Scope、动作选择、数据引用、报告版本和 Demo 审批策略决定；
- Checkpoint 与运行记录通过 run_id 关联，职责保持分离；
- 对日志详情做边界控制，不默认复制完整原始载荷和模型输入。

验证门槛：

- 重新创建服务实例后可以查询已有运行、事件、报告和处置方案；
- 运行事件 sequence 和 correlation ID 可以重建处理顺序；
- 模型、工具和审批策略事件均可定位到相同 run_id；
- 持久化内容不包含配置中的 API Key；
- 运行失败能够保存稳定错误类型和已完成阶段；
- 本步骤不引入取消、自动重试、通用队列或人工审批资源；
- 全量测试通过。

回滚点：API 可以临时切回进程内 Runner，持久化 Schema 不影响数据底座查询。

### 06：最小调查运行接口与展示迁移

目标是用正式报告和持久化运行记录完成演示闭环，消除展示层对预置场景语义的依赖。

实施内容：

- 提供 `POST /api/investigations` 和 `GET /api/investigations/{run_id}`；
- 创建接口接收案件锚点或参考数据集、Profile 和允许的运行参数；
- 查询接口返回状态、对外运行事件、InvestigationReport 和独立 ResponsePlan；
- 页面和正式调查 API 使用同一 PersistentRunService；
- 页面删除根据 `datasetId` 生成攻击影响、反证和结论的代码；
- “事件与态势”“数据与证据条件”“AI 分析与输出”全部读取后端正式契约；
- 数据页面继续展示数据接入诉求，并从 Manifest、导入事实和查询接口投影，而不是静态拼装状态；
- 研判报告与处置建议继续分开展示，模型自然语言保持中文；
- 页面只展示面向用户的阶段和关键发现，不泄漏内部 Prompt、完整模型输入和结构化调试载荷。

验证门槛：

- 恶意与合法参考场景均可通过新 API 启动并在页面完成；
- 服务重启后刷新同一 run_id 仍能恢复结果；
- 页面不存在基于数据集名称选择攻击影响或反证的逻辑；
- L0～L3 切换仍能展示数据质量改变研判边界；
- API Schema、404、失败运行、HTML 转义和长文本均有测试；
- 不新增完整案件、身份、取消、重试和人工审批 API；
- 全量测试通过。

阶段边界：本步骤验收后删除旧 Demo 运行路由和页面旧投影。

### 07：首版架构收敛与容量方案取舍

目标是让首版代码只保留目标架构需要的运行链路，并明确百万级活动假设下的工程取舍，不实施容量基准测试。

实施内容：

- 记录 SQLite 在百万级活动假设下的适用边界：批量事务写入、按租户/时间/主机/活动域建立组合索引、游标分页、避免无界扫描，并监控数据库文件增长；
- 保持查询端口与 SQLite 解耦，使后续切换关系数据库、湖仓或外部安全数据平台时不修改 LLM Tool 和研判图；
- 不生成百万级测试数据，不设置吞吐、P50/P95 或数据库大小验收门槛；容量实测进入独立性能需求；
- 完成恶意、合法、数据稀疏和特殊扩展活动的现有端到端验收；
- 将参考 Demo 默认链路收敛到 RawRecord、Activity、EvidenceReference 和正式调查 API；
- 删除失去调用方的旧 Evidence 转换、场景结论硬编码和进程内运行事实源；
- 对仍被首版能力调用的旧代码直接完成迁移，不设置弃用期或版本兼容包装；
- 加强架构测试：研判不得依赖具体存储 Adapter，展示不得依赖研判内部状态，活动模型不得依赖案件模块；
- 更新软件架构、Feature 状态、共享契约和术语。

验证门槛：

- 容量方案说明索引、分页、批量写入、增长监控和存储替换边界；
- 两种 Parser、查询接口约束、双 LLM 循环、持久化恢复和页面链路通过；
- 全量自动测试通过；
- 仓库不包含真实凭据或运行数据库；
- 首版默认运行路径不再依赖失去业务价值的旧兼容转换和进程内 `_jobs`。

## 3. 代码落点

| 能力 | 主要位置 |
|---|---|
| 跨模块契约 | `src/threat_agent/contracts/` |
| 原始记录、活动、Parser、实体和查询 | `src/threat_agent/data_foundation/` |
| EvidenceReference 与报告发布编排 | `src/threat_agent/judgment/`、`src/threat_agent/case_management/` |
| 运行、审计和持久化 Adapter | `src/threat_agent/case_management/`、`src/threat_agent/bootstrap/` |
| API、读模型和页面 | `src/threat_agent/presentation/` |
| 参考来源样例 | `demo_data/`，只保存小型版本化样例 |
| 容量设计 | 在 Feature 设计中记录百万级假设下的索引、分页、批量写入和存储替换边界 |
| 自动化验证 | `tests/` |

不新建跨领域的“platform”业务包。契约属于 `contracts`，数据事实属于 `data_foundation`，研判报告属于研判/案件发布边界，运行 API 属于 `presentation`。

## 4. 每步共同验证

每个步骤至少执行：

1. 新增能力的单元和契约测试；
2. 架构依赖测试；
3. 现有黄金 Case 与 L0～L3 Demo 回归；
4. 双循环离线 Fake 模型端到端测试；
5. `git diff --check` 和敏感配置检查；
6. 全量 `pytest`。

真实模型冒烟仅在本地凭据存在时执行，不作为离线 CI 的硬依赖。任何步骤未达到验证门槛时，不通过修改黄金结果掩盖语义退化，也不开始下一步。

## 5. 审批项

本计划请求确认：

1. 按七步顺序实施，首版发布前直接清理开发期旧路径，不建立升级兼容机制；
2. 首期物理存储继续使用 SQLite 验证语义和业务闭环，并按百万级活动进行方案取舍但不做容量实测；领域接口不暴露 SQLite；
3. 最终调查报告和数据充分性判断由 LLM 生成，确定性组件只负责事实计算、引用和实际 Scope 校验；
4. 运行持久化使用数据库记录替代 `_jobs`，但不建设通用任务队列；
5. 本期 API 只提供调查创建与查询，不扩展完整案件和审批平台；
6. RAG 继续保持接口和 Null Adapter，不在本计划中实现。
