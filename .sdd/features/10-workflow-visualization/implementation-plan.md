# Workflow Visualization — Implementation Plan

每条步骤以"改动 + 验收"闭环。整体目标：演示页步骤 03 顶部常驻一张工作流图（10 节点，忠实于真实架构），事件瀑布流在下方并带"来源节点"徽标；顺带修两个领域拆分回归（活动领域计数、数据核验复读观感）。

## 步骤 1：给事件加 first-class 节点身份

**改动**：

- `contracts/operations.py`：`OperationalEvent` 增加可选字段 `node: str = ""`（默认空串，向后兼容旧库记录）。
- `bootstrap/demo_runtime.py` `_emit()`：
  - 新增 `_NODE_BY_KIND` 默认映射（decision→plan、tool/tool_error→execute、report→compose、validation→gate、verdict→gate、response→advise、result/complete→done、run/graph→intake、repair→validate …）；
  - `safe_details` 里的 `node` 优先于默认映射（从 details 提取后再决定，最终写入 `event.node`，不进 details）。
- `bootstrap/demo.py` 显式标注歧义点（`thinking`/`repair` 等）：
  - `ObservableJudgmentPlanner.plan` → `node="plan"`，`repair` → `node="validate"`；
  - `ObservableReportComposer.compose` → `node="compose"`，`validate`/`repair` → `node="gate"`；
  - `ObservableResponsePlanner.propose` → `node="advise"`；
  - `run_demo_profile` 的 `emit("graph")` → `node="intake"`，`emit("result")` → `node="done"`，scope/response 审批 emit 按 `approval_kind` 分别标 `node="scope"` / `node="approve"`。

**验收**：`pytest -q` 全绿；`/api/investigations/{run_id}` 返回的每条 event 都带非空 `node`。

## 步骤 2：修领域拆分回归 + 研判结论归位

**改动**：

- `judgment/adapters/investigation_tools.py` `_event_details()`：`activity_type` 改为从 `_DOMAIN_TOOLS[tool_name][0]` 取领域（修"活动领域=0"），并给 tool 事件标 `node="execute"`。
- `bootstrap/demo.py`：把 `verdict`（"研判结论"）事件从 `ObservableResponsePlanner.propose` 移到 `ObservableReportComposer.compose`（`gate` 之后）发出，用 `VERDICT_LABEL_ZH`/`VERDICT_SUMMARY_ZH`；`ObservableResponsePlanner` 只发 `response`，移除 `_verdict_emitted` 相关逻辑。

**验收**：单测覆盖"`activity_type` 由工具名推导、不再依赖参数"；实际跑一次，侧栏"已查询活动领域"能正确累加、事件卡显示具体领域（如"进程与命令"）而非通用文案；"研判结论"出现在研判阶段而非处置阶段。

## 步骤 3：前端工作流图（常驻顶部）

**改动**：`presentation/api/demo_page.py`

- 新增 `WORKFLOW` 常量（10 节点 + DAG 边 + 分组），节点 id 与后端 `node` 值一一对应；
- 步骤 03 顶部用工作流图替换四段 `stage-rail`：节点卡片三态（pending/active/done），循环组 `plan/validate/execute` 用容器 + 内部箭头 + "证据充分则出循环"注释，单张 `<svg>` 连线；图常驻顶部；
- 新增 `setNode(nodeId)` 替代 `setStage(name)`：事件里的 `node` 驱动高亮，节点产出过输出即 `done`，`status=completed` 时全图 `done`；
- 事件瀑布流每条卡加"来源节点：<标签>"徽标（来自 `event.node`）；
- 修正 `evidence-count` 计数：改读 tool 事件新带回的领域字段（步骤 2 已修好源头），`seenDomains` 正常累加。

**验收**：浏览器打开页面跑一次调查，图能按当前节点高亮移动、事件卡有来源徽标、循环组与证据门槛节点清晰可见、活动领域计数正确。

## 步骤 4：全量回归 + 真实验证

**改动**：无新代码，验证收口。

**验收**：`pytest -q` 全绿；对 `c2-malicious-reference` 与 `c2-benign-reference` 各跑一次真实 LLM 调查，核对工作流图、事件来源徽标、活动领域计数、研判结论归位、交付物渲染全部正确。
