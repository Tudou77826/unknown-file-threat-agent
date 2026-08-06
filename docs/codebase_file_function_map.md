# Linux Unknown-File Threat Agent 代码工程逐文件逐函数说明

> 说明：本文档基于 `README.md`、`docs/CURRENT_PROJECT_COMPLETE_GUIDE.md`、核心 Python 代码、测试与 `cases/` 目录整理，用于汇报工程架构、实现细节、用例设计、攻击路径还原能力和后续工作方向。

## 1. 工程总体架构

本工程的目标不是让 LLM 直接下结论，而是构建一个“LLM 负责规划、确定性代码负责取证与判定”的 Linux 未知文件威胁研判系统。整体链路为：

1. `input.json` 进入 `ingestion.py`，被规范化为 `InvestigationState`。
2. `ToolRegistry` 暴露证据查询工具和确定性分析工具。
3. `Planner` 选择下一步动作，动作分为 `EvidenceRequest`、`AnalysisRequest`、`ScopeRequest` 和 `FinishRequest`。
4. `Policy` 校验动作是否合法、是否越界、是否重复、是否超预算。
5. `Evidence Tool` 从 `Repository` 查询原始事件并返回 `EvidenceBundle`。
6. `Analysis Tool` 只消费被授权的 `Evidence ID`，把证据转成 `Fact`、`Finding` 和 `Relation`。
7. `State` 负责合并证据、创建分析义务、更新 Gap / Role / Hypothesis。
8. `Verdict` 基于确定性规则给出候选结论，再由 `validate_verdict` 验证引用和证据链。
9. `reporting.py` 输出 JSON、Markdown 和 evaluation 结果。

这套结构的核心价值是：

- LLM 只负责“选什么查、查什么、是否收敛”，不负责伪造事实。
- 证据、事实、关系、结论各自有明确的创建边界。
- 攻击路径不是“文字总结”，而是由 `Relation` 构成的可验证图结构。

## 2. 目录级说明

### 2.1 `threat_agent/`

这是工程主实现目录。所有调查、分析、评分、修复和结论逻辑都在这里。

### 2.2 `cases/`

每个 case 都是一个可回放的调查场景，通常包含：

- `input.json`：告警输入。
- `events/*.jsonl` 或 `evidence.json`：原始事件或规范化证据。
- `coverage.json`：数据源可用性与完整性。
- `expected.json`：验收期望。

### 2.3 `tests/`

测试覆盖输入规范化、仓库过滤、动作校验、分析义务、Verdict 验证、跨主机、数据窃取、勒索、端到端等关键路径。

### 2.4 `docs/`

包含当前阶段设计文档、方案说明、证据要求、字段映射、场景约束等。`docs/CURRENT_PROJECT_COMPLETE_GUIDE.md` 是当前最完整的总览说明。

### 2.5 `investigation_skills/linux-unknown-file/`

调查 Skill 不提供执行能力，只提供 Linux 取证方法、替代源策略、停止条件和调查知识。

## 3. 逐文件说明

## 3.1 `threat_agent/__init__.py`

### 职责

- 仅声明包版本。
- 不引入业务逻辑。

### 函数 / 变量

- `__version__`: 包版本号，当前为 `0.1.0`。

### 评价

- 设计合理，保持轻量，不污染导入链。

## 3.2 `threat_agent/models.py`

这是整个工程最关键的 schema 文件，定义所有状态对象、动作对象、工具评分、修复对象和结论对象。

### 核心基类

#### `StrictModel`

- 继承 `pydantic.BaseModel`。
- `extra="forbid"`：禁止多余字段。
- `str_strip_whitespace=True`：自动清理字符串空白。

作用：所有业务对象都被强约束，避免 planner 或数据源塞入脏字段。

### 枚举

#### `EvidenceStatus`

- `available`
- `empty`
- `partial`
- `unavailable`
- `error`

用于证据与覆盖状态。

#### `VerdictLevel`

- `confirmed_malicious`
- `likely_malicious`
- `suspicious`
- `insufficient_evidence`
- `likely_benign`
- `benign`

用于最终案件结论。

### 实体与证据类

#### `Entity`

表示 host、file、process、endpoint、service 等实体。

#### `Evidence`

表示原子证据，包含：

- `evidence_id`
- `evidence_type`
- `domain`
- `source_system`
- `observed_at`
- `subject_refs`
- `data`
- `status`
- `limitations`
- `raw_reference`

#### `Claim`

表示初始告警或上游上下文里的未验证陈述。

### 事实与发现

#### `Fact`

确定性分析得出的“原子事实”。

#### `Finding`

规则识别出的安全行为、影响或解释。

#### `Relation`

攻击路径边，必须有 `evidence_refs`，并且源/目标实体都必须存在。

### 假设、Gap 与角色

#### `Hypothesis`

当前待验证的攻击解释，例如 backdoor_c2、data_exfiltration、ransomware。

#### `EvidenceGap`

调查问题定义，包含：

- `gap_id`
- `gap_type`
- `question`
- `reason`
- `required_evidence_types`
- `requirement_mode`
- `recommended_tools`
- `priority`
- `status`
- `resolution`
- `resolution_refs`
- `limitations`

#### `AnalysisObligation`

一旦证据足以触发某分析工具，就会创建分析义务，要求先完成该分析再继续其他分支。

#### `Coverage`

描述数据源覆盖情况，不等于“攻击不存在”。这是工程中特别重要的阴性语义对象。

#### `EvidenceRole`

描述某个 Hypothesis 需要的证据角色，如 execution、behavior、counter_evidence 等。

#### `Interpretation`

允许 LLM 基于已有 Fact/Finding 给出解释，但必须引用现有事实或发现，不能凭空造结论。

### 调查规划与评分

#### `PlannerDecision`

记录每轮规划决策：

- 决策类型
- 选择工具
- 目标 Gap / Hypothesis / EvidenceRole
- 规划摘要
- 是否修复过
- 是否 fallback

#### `ToolScore`

记录某轮候选工具的评分拆解，用于审计和排序。

#### `EvidencePack`

一次证据查询的包装对象，记录：

- 询问了什么
- 命中了什么 Gap / Role / Hypothesis
- 返回了什么证据
- Coverage 如何
- 触发了哪些分析义务
- 局限是什么

#### `RepairAction`

结构化修复动作，包含：

- 修复类型
- 触发原因
- 目标 Gap
- 推荐工具
- 证据引用
- 是否阻塞
- 尝试次数

#### `Scope`

案件当前允许调查的主机、容器、实体与时间窗口。

#### `ScopeExpansion`

跨主机扩域申请结果，带审批状态、来源和限制。

#### `Budget`

控制迭代数、工具调用数、scope 扩展数、修复数和 verdict 修复数。

### 动作 schema

#### `EvidenceRequest`

证据查询动作。

#### `AnalysisRequest`

分析动作，必须携带授权的 `evidence_refs`。

#### `ScopeRequest`

扩域动作，需要证据支持的候选主机、理由证据和请求域。

#### `FinishRequest`

结案动作，只表示“申请结束”，不代表最终可通过。

#### `InvestigationAction`

四类动作的 discriminated union。

#### `InvestigationActionResponse`

Deep Agents 结构化响应包装。

### 报告与结果

#### `EvidenceBundle`

证据工具返回值。

#### `FactFindingBundle`

分析工具返回值。

#### `CandidateVerdict`

候选结论。

#### `InvestigationState`

全局状态容器，贯穿整个引擎循环。

### 评价

- 设计成熟，职责清晰。
- 通过 Pydantic 约束把整个调查状态变成可验证对象。
- 对结论引用、证据引用、路径引用都提供了较强的结构化支持。

## 3.3 `threat_agent/ingestion.py`

负责把告警输入变成调查状态，是工程的“入口标准化层”。

### 关键函数

#### `pick(raw, name, default=None)`

- 从多个字段别名中取值。
- 兼容 PPT / 旧字段命名，例如 `File_hash`、`fileHash`、`file_hash`。

#### `millis(value)`

- 将毫秒时间戳转成 UTC datetime。
- 对空值、异常值返回 `None`。

#### `parse_detail(value)`

- 支持 `Detail` 是 dict 或 JSON string。
- 返回 `detail` 与解析限制。
- 如果 JSON 不是 object 或格式非法，会给出限制说明。

#### `initialize_state(raw)`

这是最重要的函数。

主要步骤：

1. 读取 hash、path、host_id。
2. 解析 `Detail` 中的 `context` 进程链。
3. 构造文件实体、主机实体和初始 Evidence。
4. 创建 backdoor_c2 初始 Hypothesis。
5. 创建执行、进程链、网络、远控、持久化、反证等 EvidenceGap。
6. 设置 Scope。
7. 如果输入显式声明非 C2 场景，则把 C2 相关 Gap 标记为 unresolvable 或关闭对应 Role。
8. 如有额外场景需求，调用 `activate_scenario`。

### 评价

- 输入标准化做得扎实。
- 把告警与事实区分开，避免直接把上游材料当成安全结论。
- 对 `Detail` 解析和 PPT 字段别名支持很实用。

## 3.4 `threat_agent/analyzers.py`

这是整个工程的确定性判定核心。所有分析都只消费授权证据，绝不直接读全状态做“自由推理”。

### 通用辅助

#### `_ev(state, domain, evidence_refs=None)`

- 返回指定 domain 中、状态为 available 的证据。
- 如果传入 `evidence_refs`，只允许这些 ID。
- 这是“分析隔离”的关键函数。

### C2 与进程类

#### `verify_execution`

- 从 `process_exec` 证据中确认文件执行。
- 输出 `file_executed` Fact 和 `executed_as` Relation。

#### `analyze_process_chain`

- 处理 `process_parent_relation`。
- 输出进程链验证 Fact 和 `spawned` Relation。

#### `analyze_network`

- 聚合 `network_connection`。
- 识别外联、重复连接与周期性。
- 输出 `connected_to` Relation 和周期性 Finding。

#### `analyze_remote_command`

- 结合 `network_connection`、`socket_io`、`process_parent_relation`、`child_process_exec`。
- 识别“入站数据 → 子进程命令 → 出站数据”的远控链。
- 输出关键 Finding `remote_command_execution`。

#### `analyze_persistence`

- 处理 systemd 持久化事件。
- 识别 unit write + enable + start 组合。
- 输出 `persisted_by` Relation 与 persistence Finding。

#### `analyze_reputation`

- 处理 `package_provenance` 与 `approved_endpoint`。
- 形成 `trusted_package_provenance` / `known_service_endpoint` Fact。
- 满足条件时输出 `legitimate_software_explanation` Finding。

### 文件来源

#### `analyze_file_provenance`

- 识别 file_create / file_download / file_transfer / archive_extraction / package_install / web_upload。
- 生成 origin Fact 与 relation。
- 如果包安装且签名可信，会产生良性安装解释。

### 数据窃取

#### `analyze_sensitive_discovery`

- 识别 discovery_command。
- 输出敏感发现 Fact / Finding。

#### `analyze_credential_access`

- 识别成功读取 sensitive_file_access。
- 输出 sensitive read Fact / Finding。

#### `analyze_data_staging`

- 识别 archive_create + archive_member 或 staging_file。
- 输出敏感暂存 Finding 与归档关系。

#### `analyze_data_transfer`

- 识别 network_transfer / http_upload。
- 输出 outbound transfer Fact / Finding。

#### `analyze_dns_tunneling`

- 基于高熵、长标签、足够频次识别 DNS tunnel。
- 输出 `dns_tunnel_pattern` Finding。

#### `analyze_https_exfiltration`

- 要求敏感读取、归档成员、归档传输、以及可选 baseline 反证。
- 未命中 baseline 时输出 confirmed_data_exfiltration。
- 命中 approved baseline 时输出 legitimate_backup_explanation。

#### `analyze_dns_exfiltration`

- 要求敏感读取、归档、编码 DNS 传输和 baseline。
- 与 HTTPS 路径类似，但 egress 通过 DNS。

### 勒索

#### `analyze_bulk_file_impact`

- 识别批量修改数量、速率、目录范围。
- 输出 broad_high_rate_file_impact。

#### `analyze_probable_file_encryption`

- 结合内容熵变化与改名模式判断 encryption-like transformation。

#### `analyze_recovery_inhibition`

- 处理 backup_destruction / snapshot_activity / destructive_command。
- 输出 recovery_inhibition。

#### `analyze_ransom_note`

- 统计 ransom note 创建数量。
- 多次成功才认为有效。

#### `analyze_service_disruption`

- 识别真实服务停止、失败或禁用。

#### `analyze_ransomware_chain`

- 把 bulk impact、encryption-like change、destructive impact、approved batch baseline 串起来。
- 输出 confirmed_ransomware_impact 或 legit batch explanation。

### 跨主机

#### `analyze_cross_host_path`

- 处理 file_transfer_cross_host、hash_presence、remote_login_session、host_asset_context。
- 识别直接传播、批准部署或仅有转移线索。

#### `analyze_cross_host_lead`

- 从 transfer / internal connection / shared endpoint 找到候选 host 线索。
- 为受控扩域提供依据。

### 总结

- 这里的分析器体现了工程的核心原则：**结论不是模型“猜”的，而是证据规则推出来的。**
- `Relation` 的生成逻辑为攻击路径还原提供了基础。

## 3.5 `threat_agent/repository.py`

负责把 case 数据源抽象成统一查询接口。

### 辅助函数

#### `_datetime(value)`

- 把 ISO 时间或 datetime 统一转成 datetime。

#### `_strings(value)`

- 从嵌套结构中递归提取字符串，用于实体匹配。

#### `_field(data, dotted_name)`

- 支持按点号路径读取嵌套字段，例如 `a.b.c`。

### `FixtureEvidenceRepository`

#### `__init__(case_dir)`

- 读取 `evidence.json` 和 `coverage.json`。
- 用于旧兼容或规范化 fixture。

#### `query(domain, evidence_types, state, parameters=None)`

核心行为：

- 按 domain 与 evidence_type 过滤。
- 根据 host_id、entity_ids、start_time、end_time、filters、limit 进一步筛选。
- 计算 Coverage：status、completeness、时间边界、限制。
- 返回 `EvidenceBundle`。

### `JsonlEventRepository`

#### `__init__(case_dir)`

- 读取 `events/*.jsonl`。
- 将 raw event 规范化成 `Evidence`。
- 用于 P1 以后原始事件回放。

### 评价

- 查询接口统一且具备时间覆盖语义。
- 把“没有数据”和“数据源不可用”区分开，是这套系统非常关键的一点。

## 3.6 `threat_agent/tools.py`

统一注册和暴露调查工具。

### `ToolDefinition`

描述单个工具的元信息：

- `name`
- `kind`
- `domain`
- `description`
- `handler`
- `input_schema`
- `provides_evidence_types`
- `requires_evidence_types`
- `requirements_mode`
- `resolves_gap_types`
- `repeat_policy`

### `ToolRegistry`

#### `__init__(repository)`

- 注册所有 evidence 工具与 analysis 工具。
- 为每个工具定义 schema、domain 和输入/输出约束。

#### `register(definition)`

- 注册新工具，防止重名。

#### `get(name)`

- 取工具定义。

#### `list()`

- 列出全部工具。

#### `catalog(state)`

- 根据当前状态，筛选可见工具并排序。
- 结合 `score_tool` 生成 ToolScore。
- 对跨主机场景、scope 约束、analysis prerequisite 等进行过滤。

#### `_query(...)`

- 作为证据工具的统一适配层。

#### `invoke(name, state, parameters=None)`

- evidence 工具调用 repository.query。
- analysis 工具调用对应 analyzer。

### 评价

- 工具注册和执行分层清楚。
- 动态 catalog 是 Planner 的输入来源，也是预算控制和审计的基础。

## 3.7 `threat_agent/orchestration.py`

P2.5 的核心新增编排层。

### 常量

- `PRIORITY_WEIGHT`
- `ROLE_WEIGHT`
- `DOMAIN_COST`

这些用于工具评分。

### 关键函数

#### `score_tool(state, tool, compatible_gaps, matching_roles, already_called)`

- 计算一个候选工具的综合得分。
- 考虑 Gap 优先级、Role 价值、信息增益、Coverage、反证价值、修复优先级、重复惩罚、域成本等。
- 结果写入 `ToolScore`。

#### `build_evidence_pack(...)`

- 把一条证据查询封装成 `EvidencePack`。
- 记录结果、覆盖、限制和分析义务引用。

#### `add_repair_action(...)`

- 添加去重后的 RepairAction。

#### `plan_verdict_repairs(...)`

- 当 verdict 验证失败时，按 threat_type 挑选最相关的 Gap 开展补证。

#### `apply_pending_repair(...)`

- 只应用当前允许的 pending repair。
- 若目标 Gap 仍可通过未尝试工具修复，则重新打开 Gap。

### 评价

- 这层让调查过程从“散点式执行”变成了“可审计任务包 + 可限次修复”。

## 3.8 `threat_agent/state.py`

负责状态合并与自动义务创建。

### `apply_evidence_bundle(state, bundle, registry, requested_evidence_types=None)`

主要作用：

- 合并新 evidence。
- 合并 Coverage。
- 更新相关 EvidenceGap 状态。
- 在证据满足分析前置条件时，创建 `AnalysisObligation`。
- 更新 EvidenceRole 满足状态。

### `apply_analysis_bundle(state, bundle, tool_name, evidence_refs)`

主要作用：

- 合并 facts/findings/relations。
- 对 relation 引用到的新实体进行派生创建。
- 把对应 analysis obligation 标记为 completed / failed。
- 让相关 Gap 自动进入 resolved / analyzing / partially_resolved。
- 调用 `update_hypotheses`。

### `update_hypotheses(state)`

- 根据已有事实与发现更新各类 Hypothesis 的支持度、冲突和状态。
- 把“证据驱动的假设更新”固定为本地规则，不交给 LLM。

### 评价

- 这是调查状态机的核心执行层，写得比较稳。
- 证据、义务、Gap 和 Hypothesis 的同步逻辑较完整。

## 3.9 `threat_agent/policy.py`

负责动作合法性审查。

### 辅助函数

#### `_datetime(value)`

- 解析时间参数。

#### `_contains_host(value, host_id)`

- 用于 Scope 请求中判断候选主机是否能被证据直接命名。

### `validate_action(action, state, registry)`

校验内容包括：

- 迭代预算是否耗尽。
- 工具是否存在、kind 是否匹配。
- 域是否在 scope 内。
- tool_call 是否超上限。
- EvidenceRequest 的 gap 是否存在、状态是否允许、参数是否合法、host / entity / time / limit 是否越界。
- AnalysisRequest 是否引用真实证据、是否满足 required evidence types、是否重复分析、是否匹配待处理义务。
- ScopeRequest 是否引用真实证据、候选 host 是否已经在 scope 内、是否超过审批策略、是否超过 3 个 host、domains 是否被允许、候选 host 是否被证据直接命名。
- FinishRequest 是否还有未处理义务、未尝试 gap、仍在分析中的 gap、缺失声明或虚假结案引用。

### 评价

- 这是安全边界的关键实现。
- 它确保 LLM 不能绕过系统决定性控制面。

## 3.10 `threat_agent/planner.py`

负责计划下一步做什么。

### `ACTION_ADAPTER`

- `TypeAdapter(InvestigationAction)`。
- 用于验证结构化动作 schema。

### `EmptyModelResponseError`

- 模型连续无有效响应时抛出。

### `Planner` Protocol

- 定义 `plan(state)` 接口。

### `DeterministicPlanner`

#### `sequence`

- 预定义的调查序列。
- 基本覆盖 C2、文件来源、数据窃取、勒索、跨主机等路径。

#### `analysis_requirements`

- 每个分析工具需要的 evidence types。
- 用于在已有证据条件满足时选择分析动作。

#### `plan(state)`

- 如果有 pending analysis obligation，优先补完。
- 跨主机场景下，若发现直接 transfer 但 target 未扩域，则申请 ScopeRequest。
- 按预定义序列找下一个合适的 evidence request 或 analysis request。
- 最后返回 FinishRequest。

### `state_view(state, registry)`

- 对 LLM 裁剪出相关 evidence、facts、findings、hypotheses、roles、gaps、coverage、最近工具调用、最近 evidence pack、repair、top tools 等。
- 用于 DeepAgents 的上下文输入。

### `DeepAgentsPlanner`

#### `__init__(model, registry)`

- 建立 deepagents 运行环境。
- 禁用 general purpose subagent。
- 只允许一个主调查 agent。
- 通过系统 prompt 约束模型只返回结构化决策。

#### `plan(state)`

- 若存在 pending analysis obligation，优先补完。
- 调用模型生成 JSON 决策。
- 支持 activate_scenarios、interpretation、scope_request。
- 如模型选择 `__finish__` 或 `__scope__`，按本地逻辑构造动作。
- 规划记录会写入 `PlannerDecision`。

#### `repair(state, invalid_action, validation_error)`

- 默认重走 `plan`。

#### `_finish_action(state)`

- 构造 FinishRequest。

#### `_build_action(state, catalog, tool_name)`

- 把模型输出的 tool_name 转成 EvidenceRequest 或 AnalysisRequest。

#### `_generate(instruction, attempt=1, max_attempts=3)`

- 负责流式调用模型、收集文本、解析 JSON。
- 失败时可重试，空响应则 fallback 到 catalog 排序首项。

### 评价

- DeepAgents 只负责“语义选动作”，不负责执行和判定。
- 这使得模型可以参与规划，但不会掌握安全决策权。

## 3.11 `threat_agent/engine.py`

调查主循环。

### `InvestigationEngine`

#### `__init__(registry, planner)`

- 绑定工具目录和规划器。

#### `run(state)`

主流程：

1. 增加 iteration。
2. 快到预算上限时自动加入收敛修复。
3. 生成工具目录快照并记录 ToolScore。
4. 若超迭代预算，直接给出 verdict 并结束。
5. 让 Planner 产生动作。
6. 通过 policy 校验。
7. 若校验失败，尝试 planner.repair；仍失败则记录 denied。
8. 若是 FinishRequest，先评估 verdict，再做 verdict validation 和可能的 repair。
9. 若是 ScopeRequest，按审批策略创建 ScopeExpansion，并在批准时更新 scope / entities / budget。
10. 若是 EvidenceRequest / AnalysisRequest，调用 registry.invoke。
11. 对 EvidenceBundle：合并证据、更新 gap、自动创建 evidence pack、处理替代源修复。
12. 对 FactFindingBundle：合并事实、发现和关系，更新 obligations 和 hypotheses。
13. 对错误或 denied 动作，生成相应 RepairAction。
14. 继续循环直到 state.finished。

#### `_record_denied(...)`

- 记录被拒绝的动作为 ToolCall。

#### `_fail_matching_obligations(...)`

- 失败的 analysis action 会把对应 obligation 标记为 failed。

#### `_resolve_exhausted_alternative_gaps(...)`

- 处理某些 any 模式 gap 在替代源穷尽后的 negative resolution。

### 评价

- 引擎是“策略 + 执行 + 修复 + 验证”的总控面。
- 逻辑复杂，但分层清楚，符合本项目设计目标。

## 3.12 `threat_agent/scenarios.py`

控制场景激活。

### `SCENARIO_CATALOG`

- `c2`
- `file_provenance`
- `data_exfiltration`
- `ransomware`
- `cross_host`

每个场景定义描述与推荐工具。

### `activation_catalog(state)`

- 返回当前可激活场景列表。

### `activate_scenario(state, scenario, reason_refs)`

- 只有已有 Evidence / Fact / Finding 引用才能激活。
- 会向 state 注入相应 Hypothesis、EvidenceRole 和 EvidenceGap。
- 不允许 LLM 发明场景模板。

### `add_interpretation(state, proposal, model)`

- 写入 LLM 的候选解释。
- 必须引用现有 Fact/Finding，且 confidence 合法。
- 相同解释会去重。

### 评价

- 是“受控场景路由”的实现点。
- 有效减少专项 case 中无关 C2 逻辑的噪音。

## 3.13 `threat_agent/reporting.py`

负责输出报告。

### `report_payload(state)`

- 汇总 verdict、entities、evidence、attack_path、facts、findings、hypotheses、roles、interpretations、coverage、obligations、gaps、tool_calls、planner_decisions、tool_scores、evidence_packs、repair_actions、scope、scope_expansions、verdict_validation 等。

### `evaluation_payload(state, expected=None)`

- 做验收统计：
  - 结论是否匹配 expected
  - 是否存在 unsupported edges
  - 是否有重复工具调用
  - denied/error 计数
  - unresolved critical gaps
  - verdict validation 状态
  - 整体 PASS / FAIL

### `write_reports(state, output_dir, expected=None)`

- 写 `report.json`
- 写 `report.md`
- 写 `evaluation.json`

### 评价

- 输出既能机器验收，也能人工阅读。
- attack path 的输出来源于 Relation，逻辑闭环清楚。

## 3.14 `threat_agent/verdict.py`

负责最终结论与路径校验。

### `build_attack_path(state)`

- 将 `state.relations` 按时间排序并导出。
- 这就是攻击路径还原的直接数据源。

### `evaluate_verdict(state)`

- 按预定义规则，基于 facts/findings 生成候选 verdict。
- 覆盖 backdoor_c2、data_exfiltration、ransomware、benign / insufficient_evidence 等。
- 会把支持和反证都写入 CandidateVerdict。

### `validate_verdict(state, verdict)`

- 校验 verdict 引用的 fact/finding 是否存在。
- 校验 Fact/Finding/Relation 的 evidence_refs 是否真实存在。
- 校验 Relation 是否引用存在实体。
- 校验各类 confirmed verdict 是否满足最低证据链要求。

### 评价

- 这是“结论不能乱编”的最后一道闸门。
- 对报告可信度非常关键。

## 3.15 `threat_agent/cli.py`

命令行入口。

### `run_case(case_dir, mode="deterministic", output_dir=None)`

- 读取 `input.json`。
- 初始化状态。
- 选择 `JsonlEventRepository` 或 `FixtureEvidenceRepository`。
- 按模式选择 `DeterministicPlanner` 或 `DeepAgentsPlanner`。
- 运行引擎。
- 如指定输出目录则写报告。

### `main()`

- 解析命令行参数。
- 默认 case 是 `cases/c2_malicious`。
- 打印最终 report payload。

### 评价

- 是最简单、最实用的运行入口。
- 便于离线回放和真实模型抽检。

## 3.16 `threat_agent/model_config.py`

### `build_chat_model()`

- 从 `.env` 加载 API 配置。
- 支持 `THREAT_AGENT_API_KEY` 或 `SILICONFLOW_API_KEY`。
- 读取 `THREAT_AGENT_API_BASE` 和 `MODEL_NAME`。
- 返回 `ChatOpenAI`。

### 评价

- 配置明确，但与外部模型服务耦合。
- 离线测试不依赖它，只有 DeepAgents 模式才需要。

## 3.17 `threat_agent/__pycache__` 等缓存目录

- 不属于源码逻辑。
- 不需要纳入汇报核心内容。

## 4. 测试与 Case 设计说明

## 4.1 测试层级

### `tests/test_ingestion.py`

验证：

- PPT 字段别名兼容。
- `Detail` JSON 字符串解析。
- 缺少关键锚点时拒绝输入。

### `tests/test_p0_action_contract.py`

验证：

- action schema 是否拒绝空目标。
- invent evidence ref 是否被拒绝。
- catalog 是否根据 evidence prerequisite 收敛。
- Engine 是否允许一次 policy repair。

### `tests/test_p1_repository_and_path.py`

验证：

- repository 的 host / entity / time / limit 过滤。
- 原始事件里没有预写结论。
- attack path 边的 evidence 和 entity 引用都真实存在。
- remote command finding 是否由独立原始事件导出。

### `tests/test_p1_investigation_loop.py`

验证：

- evidence collection 是否自动创建 analysis obligation。
- Finish gate 是否阻止未分析结案。
- DeepAgents 是否优先处理 pending obligation。
- 空响应 fallback 是否生效。

### `tests/test_p2_cross_host.py`

验证：

- 直接 transfer + login + presence + execution 是否形成横向传播。
- approved deployment 是否为反证。
- shared C2 是否不能证明传播。
- scope request 是否必须被证据直接命名。
- DeepAgents scope proposal 是否会被本地规范化。

### `tests/test_p2_data_exfiltration.py`

验证：

- HTTPS / DNS 窃密是否形成完整链。
- 批准备份是否作为合法解释。
- 证据不足是否保持 insufficiency。
- 所有 exfil path 边都可回溯证据和实体。

### `tests/test_end_to_end.py`

验证：

- c2_malicious 是否确认 backdoor_c2。
- c2_benign 是否不被误判。
- insufficient_evidence 是否输出证据不足。
- 所有输出引用是否可解析。

## 4.2 Case 设计原则

每个 case 都围绕一个明确问题设计：

- 恶意 case：证据链必须完整且能闭环。
- 良性 case：必须有反证，防止误报。
- 证据不足 case：必须表现为 unavailable / partial / insufficient，而不是强行给黑结论。

### 典型 case

- `c2_malicious`：执行、祖先关系、周期外联、远控、systemd 持久化。
- `c2_benign`：签名包、批准端点、正常监控流量、系统服务。
- `insufficient_evidence`：有执行痕迹，但关键网络/持久化源不可用。
- `exfil_https_malicious`：敏感访问 + staging + HTTPS 外传。
- `exfil_dns_malicious`：敏感访问 + staging + DNS tunnel 外传。
- `exfil_benign_backup`：批准同步/备份反证。
- `ransomware_malicious`：批量修改 + 内容变化 + 重命名 + 恢复破坏。
- `cross_host_malicious`：直接 transfer + 远程登录 + 目标执行。
- `cross_host_shared_c2_only`：只有共享外联，不足以证明传播。
- `cross_host_scope_denied`：扩域请求受审批限制。

## 5. 攻击路径还原是否实现

结论：**已实现**。

实现链路是：

1. Analyzer 根据原始证据生成 `Relation`。
2. `apply_analysis_bundle` 将 `Relation` 写入 `state.relations`。
3. `build_attack_path` 将 `state.relations` 按时间排序导出。
4. `reporting.py` 将 attack path 写入报告。
5. 测试校验 relation 的 evidence_refs、source/target entity 都存在。

因此，攻击路径不是手工拼接，也不是 LLM 口头描述，而是“证据驱动的关系图输出”。

## 6. 汇报时可以直接说的结论

- 这个工程不是一个“只会聊天的 Agent”，而是一个完整的证据驱动调查系统。
- LLM 只负责规划和解释，事实、发现、关系、结论都由确定性逻辑控制。
- case 设计覆盖了恶意、良性、证据不足三类对照。
- 攻击路径还原已经实现，且可以回溯到真实 Evidence ID。
- P2.5 的新增重点是 ToolScore、EvidencePack、RepairAction、预算收敛和状态裁剪，让系统更可审计、更可控。

## 7. 汇报后下一步工作方向

如果汇报结束，下一步建议优先做下面几件事：

1. **接真实数据源最小切片**
   - 先接进程、文件、网络三个域。
   - 保持当前 repository 接口不变，只换适配器。

2. **做真实案件回放评估**
   - 用脱敏案件回放。
   - 统计 tool 命中率、coverage、verdict 准确率、误报/漏报和模型调用成本。

3. **补强生产化能力**
   - 引入状态持久化、案件恢复、服务化接口、审计日志。
   - 这一步比继续堆规则更有价值。

4. **扩展场景而不是扩散规则**
   - 先把容器 / Kubernetes / 额外勒索样本 / 静态样本分析纳入受控场景模板。
   - 不要让 LLM 直接发明新类型的事实或动作。

5. **做校准而不是只做功能堆叠**
   - 用真实数据校准阈值。
   - 重点看 coverage 缺失时的行为是否仍然保守。

## 8. 简短结论

这套工程目前已经实现了“未知文件攻击路径还原”的主要功能闭环，而且不是单点脚本，而是一个由输入规范化、证据查询、确定性分析、结论验证和报告输出组成的完整框架。汇报之后最值得推进的方向是：接真实数据源、做回放评估、补生产化能力，而不是继续无限增加规则。
