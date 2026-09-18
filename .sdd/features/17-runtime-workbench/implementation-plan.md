# Runtime Workbench — Implementation Plan

四个步骤，每步以全量测试绿 + 新增架构规则绿收口。M3（第 4 步）依赖 Feature 16 落地，允许后置。

## 步骤 1：运行底座通用化（M1 前半）

**内容**

1. `contracts/intake.py`、`contracts/workbench.py`：AlertIntakeRequest、RunControlAction、Trajectory*、Approval*、Checkpoint* 契约。
2. `case_management/ports/execution.py`：ExecutionPort 协议；`case_management/application/run_service.py`：运行生命周期（create / start / list / 重启孤儿标记 / replay），收编 DemoRunService 的事件发射、脱敏（`_safe_details` 等价逻辑上移为共享工具）、审计逻辑；单执行线程互斥。
3. `bootstrap/workbench_bindings.py`：ExecutionPort 实现（收编 `bootstrap/demo.py` 执行函数，middleware 运行时装配不变）；SqliteSaver 成为运行默认（settings 开关，Memory 保留测试用）。
4. 路由与页面最小面：`/api/runs`、`/api/runs/{id}` + 案件列表页、运行列表页。
5. `DemoRunService` 与 `/demo` 演示执行路径退役：演示页改读 RunService（只读剧本模式）。

**验证门槛**

- 新增单测：RunService 生命周期状态机、重启孤儿恢复（kill 模拟：预置 running 记录后调恢复逻辑）、replay、互斥（并发 start 串行化）。
- 兼容回归：现 demo 页双数据集经 RunService 跑通（真 LLM 回归沿用既有 C2 双数据集口径）。
- 新架构规则：observability 隔离规则先行落测试（此时 observability 尚未存在，规则以"无业务模块 import"形式可测）。
- 全仓测试绿。

## 步骤 2：可观测旁路 + 调测面（M1 后半）

**内容**

1. `observability/ports/trace_sink.py` + `adapters/langfuse_sink.py`（import 守卫、NullSink 降级）；bootstrap 装配 callback handler；`observability_degraded` 事件。
2. `case_management/application/debug_service.py`：checkpoint 历史（get_state_history → CheckpointRef 列表）、状态摘要、恢复（指定 checkpoint_id + 可选覆盖，恢复前快照审计）；`/api/debug/runs/{id}/checkpoints`、`/api/debug/runs/{id}/resume`。
3. `case_management/application/trajectory.py`：OperationalEvent → TrajectoryReadModel 投影（按轮分组、observation、totals）。
4. 三栏轨迹页 + 调试面板页（Jinja2/HTMX）；知识咨询面板（7 态、query_id 关联展示）。

**验证门槛**

- 降级测试：sink 抛错 / 未安装时运行不受影响且产出 degraded 事件。
- 时间旅行端到端：同一 run 从中途 checkpoint 恢复重跑到完成，产物与事件链一致；恢复动作有审计记录。
- 轨迹投影：双数据集真 LLM 运行后 TrajectoryReadModel 轮次分组、token 合计与账本一致。
- 全仓测试绿（含新架构规则：observability 只依赖 contracts、仅 bootstrap 装配）。

## 步骤 3：真实输入 + 审批台（M2）

**内容**

1. `intake.py` 扩展：alert_json 来源（AlertIntakeRequest 校验 + 原始载荷入账本）；`/api/intake` + 建案页；参考数据集并列为来源之一。
2. 审批中断载荷 v2（comment / edited_plan 可选，v1 兼容）；`edited_plan` 经 ResponsePlan 契约 + 处置校验器重验，失败走既有 graded-retry 语义；`approval_service.py`：待审批列表 + 四态决策 + 审计（decision_kind）；`/api/approvals` + 审批台页（动作 diff 式呈现、契约驱动编辑表单）。
3. SSE：`/api/runs/{id}/events/stream`（序列号游标推送）；运行视图改 SSE 实时。
4. 报告审阅页：证据引用点击 → `/api/ledger/{query_id}` 回溯工具调用与原始返回；知识咨询跨栏联动。

**验证门槛**

- 端到端：真实告警 JSON 建案→调查→审批（accept / respond / edit / ignore 四态各一）→报告闭环；edit 路径覆盖"编辑后校验失败被拒"用例。
- v1 中断载荷兼容回归（既有测试不改语义通过）。
- 重启恢复：待审批 run 重启后仍在待审列表，决策可继续。
- 脱敏回归：轨迹 / 审批 / 回溯端点响应过脱敏规则（apikey/secret/prompt 类键不外泄）。
- 全仓测试绿。

## 步骤 4：评测运行面挂载（M3，依赖 Feature 16）

**内容**

1. `bootstrap/workbench_bindings.py` 内实现 `WorkbenchTaskAdapter`（agent_eval TaskAdapter 协议：in-process 调 RunService，runtime_store 读产物）。
2. smoke 套件经平台运行面跑通的接线与文档。

**验证门槛**

- Feature 16 smoke 子集（≤12 案例）经 adapter 跑通，RunRecord 与账本一致。
- adapter 不引入平台 → 框架的反向依赖（agent_eval 不 import threat_agent）。
- 全仓测试绿。

## 交付纪律

- 每步收口跑 `pytest`（全量）+ `test_architecture_dependencies`；真 LLM 回归仅步骤 1、2、3 要求。
- 文档随实现同步：README 状态、design 与实现冲突时修文档或标注。
