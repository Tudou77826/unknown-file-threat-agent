# Workflow Visualization — Design

## 1. 现状

演示页（`/demo/{dataset_id}`，步骤 03）目前用一个**线性四段条**表达流程：

> 理解告警 → 核验证据 → 形成研判 → 制定处置

右边是一条**扁平事件流**，左边一个"调查进度"侧栏，最下面是折叠的"模型完整对话与工具调用"调试视图。

三个问题：

1. **流程被压成四步线性条，和真实架构对不上。** 真实架构是两层嵌套图：
   - 外层 `CaseGraph`：研判 → 发布 → 处置建议 → 审批；
   - 内层 `JudgmentGraph`：规划动作 → 校验 → 执行查询 →（循环）→ 生成报告；
   - 报告生成链路里还嵌着一道**证据充分性再确认**守卫（`evidence_gate.py`，只降级不升级）。
   四步条里既看不到"调查是循环的"，也看不到"证据充分性再确认"这个守卫。

2. **事件流里看不出"这条输出是哪个节点产的"。** 事件只有 `kind`（thinking/decision/tool/report/…）和一段文字，没有"来源节点"身份。观众无法把一条输出和图上某个节点对上号。

3. **两个可见 bug（feature 09 领域拆分引入的回归）：**
   - 侧栏"已查询活动领域"恒为 `0`。领域拆分后，工具名即领域（如 `query_process_activities`），`activity_type` 参数被移除；但 `InvestigationToolGateway._event_details` 仍读 `arguments.get("activity_type")`，拿到 `None`，前端 `d.activity_type` 落空，计数永远不涨。
   - 事件流出现"数据核验：query_process_activities"重复 3 遍的观感。原因是上面 `activity_type` 丢失后，前端只能退化成通用文案，且模型确实多次调用同一领域工具，观感像复读。

事件链路现状（关键）：`Observable*` 包装器与网关调用 `emit(kind, message, details)` → `DemoRunService._emit` 按 `_EVENT_TYPE` 映射 event_type、按 `_STAGE_BY_KIND` 映射 stage → 落库为 `OperationalEvent` → 前端 `renderEvent` 消费 `details.kind`。当前 `stage` 是粗粒度的（initializing / investigating / judgment / reporting / response_advisory / approval / publishing / published），整个调查循环都归在 `investigating` 里。

## 2. 目标

1. 页面上有一张**工作流图**，能回答三件事：整体流程是什么、**当前在哪个节点**、**当前输出是哪个节点产的**。
2. 这张图**忠实于真实架构**：调查循环（规划→校验→执行）作为循环呈现，证据充分性再确认作为独立守卫节点呈现，处置建议单独呈现。
3. 顺带修掉上面两个 bug，因为"执行查询"节点要正确显示查了哪个领域，依赖第 1 个 bug 的修复。

非目标：不引入前端构建链 / 图形库；保持现在"单文件 server 渲染 HTML + 原生 JS"的形态。不改变研判与处置的业务逻辑。

## 3. 做法

### 3.1 规范化工作流节点模型（新增常量）

定义一份稳定节点表 + DAG 边，作为前端图与后端事件映射的共同依据。节点（稳定 id + 中文标签 + 分组）：

| id | 标签 | 分组 | 说明 |
|---|---|---|---|
| readiness | 数据就绪度 | 入口 | 运行前评估可见数据源（步骤 02 完成，图上置灰标注） |
| intake | 告警接入 | 调查 | 理解告警、资产、初始态势 |
| plan | 规划调查 | 循环 | 研判模型选工具/填参数/判断证据是否充分 |
| validate | 校验动作 | 循环 | 策略校验 + 修复非法动作 |
| execute | 执行查询 | 循环 | 数据工具网关查活动数据 |
| scope | 范围扩展 | 调查 | 跨主机申请（demo 策略拒绝） |
| compose | 生成研判 | 研判 | 报告模型综合证据下结论 |
| gate | 证据充分性再确认 | 研判 | 防幻觉守卫：只降级、不升级 |
| advise | 处置建议 | 处置 | 处置模型生成建议 |
| done | 完成 | 出口 | 交付物发布 |

DAG 主干：`readiness → intake → [plan ⇄ validate ⇄ execute] → compose → gate → advise → done`；`plan` 在模型调用 `request_scope_expansion` 时进 `scope`，`scope` 返回后回 `plan`；`plan` 在模型调用 `finish_investigation` 时直接进 `compose`。

循环组 `[plan/validate/execute]` 在图上渲染为一个"调查循环"容器，容器内画内部箭头，容器外只画一条"证据充分→生成研判"的出边。

### 3.2 事件增加 first-class 节点身份

`OperationalEvent` 增加可选字段 `node: str = ""`（默认空串，向后兼容，旧库记录缺字段时用默认值补齐）。`DemoRunService._emit` 里：

- 新增 `_NODE_BY_KIND` 默认映射（decision→plan、tool/tool_error→execute、report→compose、validation→gate、response→advise、result/complete→done、run/graph→intake、repair→validate …）；
- `details` 里的显式 `node` 优先于默认映射（覆盖 `thinking` 这类歧义 kind）。

歧义点显式标注（改 `demo.py` 的 `Observable*` 包装器，改动小且集中）：

- `ObservableJudgmentPlanner.plan` → `node="plan"`；
- `ObservableJudgmentPlanner.repair` → `node="validate"`；
- 网关 `invoke` 的 tool 事件 → `node="execute"`，且 `_event_details` 改为从 `_DOMAIN_TOOLS` 取领域（修 bug 1），不再读 `arguments.activity_type`；
- `ObservableReportComposer.compose` → `node="compose"`，`validate` → `node="gate"`，`repair` → `node="gate"`；
- `ObservableResponsePlanner.propose` → `node="advise"`；
- `run_demo_profile` 里 `emit("graph")` → `node="intake"`，`emit("result")` → `node="done"`，scope/response 审批 emit 按 `approval_kind` 分别标 `node="scope"` / `node="approve"`。

### 3.3 研判结论事件归位

现状 `verdict`（"研判结论"）是在 `ObservableResponsePlanner.propose` 里发出的（处置阶段才补发研判结论），和"来源节点"语义冲突。改为：把 `verdict` 事件移到 `ObservableReportComposer`（`gate` 节点之后）发出，保留去重标志；`ObservableResponsePlanner` 只发 `response`。这样"研判结论"这条输出的来源节点就是 `gate`，观感正确。

### 3.4 前端工作流图（常驻顶部指示，替换四段条）

布局要求（已确认）：**工作流图固定在步骤 03 顶部，作为常驻指示**；详细内容（事件瀑布流、调查进度侧栏、交付物）保持在图下方，不做成弹层或折叠。

在步骤 03 的 `stage-rail` 位置渲染一张工作流图，用原生 JS + CSS + 单张 `<svg>` 连线（无构建链、无外部库）：

- `WORKFLOW` JS 常量：节点表（id/label/group）+ 边表；
- 每个节点卡片三种态：`pending`（灰）/ `active`（高亮，脉动）/ `done`（绿）；
- 当前节点由事件里的 `node` 驱动：`setNode(node)` 高亮；节点产出过至少一条输出即标记 `done`；
- 事件瀑布流里每条事件卡增加"来源节点：<标签>"小徽标，来自 `event.node`；
- 循环组 `plan/validate/execute` 用容器 + 内部箭头 + "证据充分则出循环"注释表达；
- 运行完成（`status=completed`）时全图置 `done`；
- 图在调查运行期间**始终可见**（随页面滚动在步骤 03 顶部保持可参考，不因瀑布流变长而消失）。

## 4. 已确认决策

1. **节点粒度**：按 10 个节点（含"证据充分性再确认"独立成节点、循环拆成 plan/validate/execute 三节点）。
2. **布局**：工作流图常驻顶部作为指示；详细内容与事件瀑布流在下方。
3. **两个 bug 并入本 Feature 一起修**：改完需实际运行验证，遇到问题即修。
4. **图必须忠实于真实架构**：调查循环、证据充分性再确认、处置建议，全部如实呈现；不沿用四步线性条。
5. **不引入前端构建链或图形库**：保持单文件 server 渲染 HTML + 原生 JS + SVG。

> 实现细节（不另行审批）：`node` 作为 `OperationalEvent` 的 first-class 字段（默认空串、向后兼容），而非塞进 `details`——"当前在哪个节点"是核心信号，值得一等字段。
