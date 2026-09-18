# Runtime Workbench — Design

## 1. 背景与现状

现演示页（`presentation/api/demo_page.py` + `routes.py`）是架构阶段的 walkthrough 产物：三页结构中最大篇幅是数据接入诉求表；入口只认两个预置参考数据集；流程是"启动→轮询→重看"的单次播放制。审批中断不可操作、checkpointer 不可续跑回放、知识咨询（7 态访问状态、query_id 审计关联）无展示、报告证据引用不可回溯——只能演示，不能使用和调试。

选型结论见 [`outputs/runtime-platform/platform-selection.md`](../../../outputs/runtime-platform/platform-selection.md)（2026-09 调研）：运行底座保留自研 FastAPI，不迁移 LangGraph Agent Server（Studio / Agent Inbox 均需 LangSmith 云侧账号，违反数据不出域与可离线约束）；观测用自托管 Langfuse；审批台与案件工作台自研，交互模型借鉴 Agent Inbox 四态；评测运行面适配 Feature 16 的 `agent_eval` 框架。对话型 / 编码型 Agent UI（DSH、OpenHands、Cline 等）不作为底座，但其"对话流净化"三栏语法与 checkpoint 恢复、diff 式审批语法被吸收为界面信息架构。

前提（已确认）：近期用户只有我们自己（调测 + 内部演练）；本机起服务即可；近期接入真实输入。

### 可复用资产盘点

| 既有资产 | 工作台角色 | 缺口 |
|---|---|---|
| `SQLiteInvestigationRuntimeStore`（runs / events / artifacts / audit 持久化） | 运行列表、轨迹、审批、回溯的唯一数据源 | 无运行控制（恢复 / 重放）入口 |
| `OperationalEvent`（kind / node / stage / token_usage / retry_count / details 含模型完整输入输出） | 轨迹视图的原始流 | 无按轮分组的投影读模型 |
| 案件父图审批中断 + `resume_response` | 审批台的后端 | 中断载荷无 comment / edited_plan；无待审批查询面 |
| `adapters/checkpointing.py`（Memory / SqliteSaver + 定制序列化器） | 断点续跑 / 时间旅行 | Sqlite 未成为运行默认；无状态历史查询 |
| `bootstrap/demo.py` 的执行函数（middleware 运行时装配） | 运行执行器 | 绑定 demo 专属签名（dataset_id / profile_id） |
| 知识咨询记录（7 态、query_id、按源隔离） | 调测面的知识面板 | 无任何 UI 呈现 |
| `_safe_details` 脱敏、`bind_execution_context` 入口绑定 | 安全边界延续 | 需在新服务与新端点上同样成立 |

## 2. 目标与非目标

### 目标

1. **使用面**：案件列表与详情、建案（真实告警 JSON 为一等来源，参考数据集降级为预设之一）、运行视图（SSE 实时）、审批台（四态）、报告审阅（证据引用回溯到工具调用与原始返回）。
2. **调测面**：按轮组织的三栏轨迹视图、checkpoint 历史 / 状态摘要 / 恢复重跑、知识咨询面板、可观测旁路（Langfuse，按案件聚合全轨迹）。
3. **评测挂载**：为 Feature 16 的 `agent_eval` 框架提供运行面适配器，批跑经平台执行并读取产物。
4. **架构不变式**：平台不新增业务层——所有展示来自账本 / 检查点 / read model，所有操作走框架入口；既有架构测试全部保持绿，并新增工作台专属依赖规则。

### 非目标

- 多用户、RBAC、LDAP（单机单租户延续，身份留待独立需求）；
- 生产处置动作执行（处置建议与执行隔离的既有边界不变）；
- React/Vite SPA（Jinja2 + HTMX 起步；升级触发条件见第 9 节）；
- LangSmith Studio / Agent Inbox 进入核心链路（仅作可选附件，见第 6 节）；
- 评测框架本体（Feature 16 职责）、生产数据源接入（Feature 01 职责）、docker 化部署编排（后置独立需求）；
- 现演示页不删除：收敛为只读"剧本模式"，工作台成为默认入口。

## 3. 总体架构

```
浏览器（Jinja2 + HTMX，与 API 同一 FastAPI 进程）
│   案件工作台 · 运行视图(SSE) · 审批台 · 报告审阅 · 调试面板
▼  REST / SSE
presentation/api/routes        仅消费 contracts + 自有 Port 协议（既有规则）
▼  注入（bootstrap 组合根装配）
case_management/application    RunService · ApprovalService · DebugService · trajectory 投影
│        │                            │
│        ▼ 调用                        ▼ 读取
│   ExecutionPort ── bootstrap 实现 ──▶ 案件父图（双循环 + 审批中断 + middleware 运行时）
│                                            │
│        ┌───────────────────────────────────┘
▼        ▼
SQLiteInvestigationRuntimeStore（runs/events/artifacts/audit）   checkpointer（SqliteSaver）

旁路① observability.TraceSink → Langfuse   （callback 级旁路，失败仅降级，业务模块零感知）
旁路② agent_eval TaskAdapter → RunService   （离线批跑，Feature 16 框架调度）
```

要点：

- **运行执行与业务编排分离**：`RunService` 管运行生命周期记录（创建 / 状态迁移 / 事件 / 审计），执行委托给 `ExecutionPort`，由 bootstrap 用现 middleware 运行时实现。case_management 定义 Port，bootstrap 实现组合——依赖方向与 `middleware_bindings` 同构。
- **可观测是旁路**：引擎与运行服务不 import observability；Langfuse 经 LangChain callback 挂接（bootstrap 装配处注入 handler），故障只降级观测。
- **单进程模型与写者唯一**：本机形态下运行执行沿用后台线程 + SQLite（与现 DemoRunService 相同）；每 run 至多一个执行线程，重启后由 RunService 将孤儿 running 标记为 failed（可重放）。运行存储的**写者清单唯一**：run 行只由 RunService 写；ApprovalService 只追加审批审计；DebugService 只追加恢复审计、不改 run 状态——写者归属由架构测试锁定（见第 4 节规则 5）。

## 4. 模块划分

```
src/threat_agent/
├── contracts/
│   ├── intake.py                 新：AlertIntakeRequest / IntakeResult
│   └── workbench.py              新：TrajectoryReadModel / TrajectoryRound / TrajectoryEntry /
│                                    ApprovalRequestReadModel / ApprovalDecision /
│                                    CheckpointRef / DebugStateSummary / RunControlAction
├── case_management/
│   ├── application/
│   │   ├── run_service.py        新：运行生命周期（create/start/list/重启恢复/replay）
│   │   ├── approval_service.py   新：待审批列表 + 四态决策（写审计）
│   │   ├── debug_service.py      新：checkpoint 历史 / 状态摘要 / 恢复
│   │   ├── trajectory.py         新：OperationalEvent → TrajectoryReadModel 纯投影
│   │   └── intake.py             扩展：真实告警建案（现 reference intake 并列为来源之一）
│   ├── ports/
│   │   └── execution.py          新：ExecutionPort 协议
│   └── adapters/
│       └── checkpointing.py      既有：SqliteSaver 成为运行默认（settings 开关）
├── observability/                新切片
│   ├── ports/trace_sink.py       TraceSink 协议（start_run/span 元数据约定）
│   └── adapters/langfuse_sink.py 可选依赖（import 守卫 + 未安装/故障降级为 NullSink）
├── presentation/
│   ├── api/routes.py             扩展：/api/runs /api/approvals /api/debug /api/intake + SSE
│   └── pages/                    新：Jinja2 模板（工作台 / 运行 / 审批 / 报告 / 调试）+ HTMX
└── bootstrap/
    ├── workbench_bindings.py     新：ExecutionPort 实现（收编 demo.py 执行逻辑）+
    │                             Langfuse sink 装配 + 依赖注入
    └── settings.py               扩展：workbench.* 与 observability.* 配置节
```

### 新增架构测试规则（并入 test_architecture_dependencies）

1. `observability` 不被任何业务模块 import；只依赖 contracts；仅 bootstrap 装配。
2. `presentation` 新增页面与路由延续既有规则：只消费 contracts 与 presentation 自有 Port 协议。
3. run / approval / debug 服务只消费 case_management 内部与 contracts；执行上下文绑定只在 RunService / graph 入口（框架入口不变式）。
4. TraceSink 抛错不得外溢：观测故障只产生 `observability_degraded` 事件（降级测试固定此行为）。
5. `runtime_store` 的 run 行写操作（create/update）只允许出现在 `run_service`；approval / debug / trajectory 对其只读——防止多服务各自迁移状态导致生命周期状态机失控。

## 5. 核心契约

全部为 StrictModel，进 `contracts/`（ presentation 可消费）。

```python
class AlertIntakeRequest(StrictModel):
    tenant_id: str
    source: Literal["alert_json", "reference_dataset"]
    alert_id: str                  # alert_json 必填；参考数据集来源可空
    host_ref: str                  # 单主机边界的主机标识
    file_path: str | None = None
    file_sha256: str | None = None
    detected_at: datetime
    summary: str | None = None
    raw: dict = Field(default_factory=dict)   # 原始告警载荷，原样入账本

class TrajectoryEntry(StrictModel):
    event_id: str
    kind: str                      # model_input / model_output / tool / tool_error / validation / repair / ...
    node: str
    sequence: int
    duration_ms: int | None = None
    token_usage: dict = Field(default_factory=dict)
    retry_count: int = 0
    summary: str                   # 主栏一行摘要
    detail: dict = Field(default_factory=dict)   # 侧栏折叠载荷（经 _safe_details 脱敏）
    evidence_refs: list[str] = Field(default_factory=list)      # 可回溯 query_id / ledger ref
    consultation_ids: list[str] = Field(default_factory=list)   # 知识咨询关联

class TrajectoryRound(StrictModel):
    index: int
    observation: str | None = None   # round 事件的观察句
    entries: list[TrajectoryEntry] = Field(default_factory=list)

class TrajectoryReadModel(StrictModel):
    run_id: str
    case_id: str
    rounds: list[TrajectoryRound] = Field(default_factory=list)
    phase_entries: list[TrajectoryEntry] = Field(default_factory=list)  # 非循环阶段
    totals: dict = Field(default_factory=dict)   # token / 耗时 / 重试合计

class ApprovalDecision(StrictModel):
    decision: Literal["accept", "edit", "respond", "ignore"]   # Agent Inbox 四态语义
    decided_by: str
    comment: str | None = None
    edited_plan: dict | None = None   # decision=edit 必填；须通过 ResponsePlan 契约与处置校验

class CheckpointRef(StrictModel):
    checkpoint_id: str
    parent_checkpoint_id: str | None = None
    step: int
    node: str | None = None
    created_at: datetime
    metadata: dict = Field(default_factory=dict)

class DebugStateSummary(StrictModel):
    checkpoint: CheckpointRef
    node_summaries: dict = Field(default_factory=dict)   # 精简状态，不含大载荷
```

### 审批中断载荷 v2（case_management 图，向后兼容）

现中断值校验只接受 `{"approved": bool, "approved_by": ...}`。扩展为：

```python
{"approved": bool, "approved_by": str, "comment": str | None, "edited_plan": dict | None}
```

- `accept` → `approved=True`；`respond`（驳回并附意见）与 `ignore` → `approved=False`，`decision_kind` 记入审计；`edit` → `edited_plan` 经 ResponsePlan 契约与处置校验器重验通过后替换待审计划再继续。v1 形态调用保持可用（comment / edited_plan 可选）。

## 6. 与外部组件的边界

| 组件 | 边界 |
|---|---|
| Langfuse | 自托管，docker compose 可选 profile；`observability/adapters/langfuse_sink.py` import 守卫，未安装或故障自动降级 NullSink 并发 `observability_degraded` 事件。session = graph_thread_id，tags = [case_id, 来源, profile]，metadata 携带 query_id 贯穿 |
| LangSmith Studio / Agent Inbox | 不进核心链路。开发期如需 Studio 时间旅行可视化，以可选附件文档说明其 LangSmith 登录前提；审批交互规格已抄收为四态，无需引入 |
| agent_eval（Feature 16） | 平台只提供 `WorkbenchTaskAdapter`（实现其 TaskAdapter 协议：in-process 调 RunService + 从 runtime_store 读产物），批跑调度、打分、pass^k 全在框架侧。落点 bootstrap（组合根），与 16 实施时对齐。Inspect AI 保持 16 已定的"抄架构不引依赖"结论与复核条件，本 Feature 不改变该决策 |
| 演示页 | `/demo` 保留为只读剧本模式（数据与页面不改），工作台成为默认首页；`DemoRunService` 退役，其事件发射 / 脱敏 / 审计逻辑收编进 RunService。**删除触发条件**：工作台剧本模式能复现 walkthrough 全流程后，删除演示页模板与数据装配——冻结的双前端只允许临时存在，避免渲染路径漂移 |

## 7. 界面信息架构（三栏轨迹语法）

- **左栏（案件档案）**：资产上下文、数据来源与等级、预算消耗、知识命中摘要。
- **主栏（轮次叙述）**：`round` 事件的观察句按轮分组；非循环阶段（接入 / 研判 / 报告 / 审批 / 处置）作为阶段卡。
- **右栏（折叠明细）**：每轮的 model_input / model_output / tool / tool_error / validation / repair 折叠卡；证据引用（query_id）与知识咨询（consultation_id）点击跨栏联动到账本与知识面板。
- **审批台**：渲染待审 ResponsePlan（动作 diff 式呈现：对什么资源做什么、影响、审批类别），四态操作；`edit` 提供表单化字段编辑（契约驱动，非自由文本）。
- **调试面板**：checkpoint 时间线（DebugStateSummary），任意节点"从此恢复"按钮（携带可选状态覆盖），与 Cline/ZCode 的 checkpoint restore 语法一致。

## 8. 里程碑

| 里程碑 | 内容 | 验收 |
|---|---|---|
| M1 调测可用 | RunService + ExecutionPort（收编 demo 执行）；SqliteSaver 运行默认 + 重启恢复；调试端点与页面；轨迹三栏视图；Langfuse 旁路 | 任一运行可从任意 checkpoint 恢复重跑；Langfuse 按案件看全轨迹；kill 进程后孤儿 run 标记 failed 且可重放；全量测试 + 新架构规则绿 |
| M2 真实输入 | intake API + 页面（alert_json v0）；审批台四态（中断载荷 v2 + edited_plan 重验）；SSE 运行视图；证据引用回溯 | 一条真实告警 JSON 建案→调查→审批（含编辑重验）→报告闭环；重启后待审批可恢复决策；v1 中断载荷兼容回归 |
| M3 评测挂载 | WorkbenchTaskAdapter + smoke 批跑经平台；运行面产物读取 | Feature 16 smoke 套件经平台运行面跑通并产出基线（依赖 16 落地，可后置） |

## 9. 风险与边界

- **SQLite 并发写**：单进程单执行线程约束写进 RunService（互斥），超越单机形态时切换 PostgresSaver + 队列，属独立需求。
- **中断载荷演进**：v2 字段全部可选，v1 调用方不破坏；`edited_plan` 重验失败按既有 graded-retry 语义返回校验错误，不静默放行。
- **Langfuse 维护成本**：作为可选 profile，关闭时系统全功能可用（NullSink）；若后续嫌重可换 Phoenix（同为 TraceSink 适配器，接口不变）。
- **HTMX 复杂度上限**：出现跨页富交互（拖拽、实时协作图）再评估 React；触发前不引入构建链。
- **安全不变式**：所有新端点过 `_safe_details` 等价脱敏；调试端点由 `workbench.debug_enabled` 开关（默认本机 true，共享部署必须显式关闭）；调试恢复**必须复用案件图既有入口**（与 `resume_response` 同一 bind 与边界校验路径），禁止绕过策略直连 checkpointer 执行——这是本 Feature 最需要看防的"合法后门"；执行上下文绑定不变式由架构测试看护。
