# 模型迁移 — 退役确定性判恶，统一到 AI 判恶 + 新活动模型

## 1. 结论（先说规模，不回避）

边界 B 不是"改几个契约字段"，而是**删掉半套系统**。当前仓库里三块东西缠在一起：

| 块 | 内容 | 去留 |
|---|---|---|
| 新活动模型 | `Activity`/`EvidenceReference`/`ObservedRelation` + SQLite 存储/查询/接入 | **留**（真实架构） |
| 确定性判恶 | `analyzers.py`/`verdict.py`/`scenarios.py`/`DeterministicPlanner`/`ToolRegistry`/`EvidenceGap`/`EvidenceRole` | **删**（用户否定的"代码 if-else 判恶"） |
| 在线 AI 判恶残留 | 报告契约 + 交接契约 + 展示层还在读 `state.facts/findings/relations`（这三个字段在线路径永远为空） | **重写对齐新模型** |

上一轮两个瑕疵（处置 0 动作、报告大串剔除 limitation）就是第 3 块读到了第 2 块的旧字段。

## 2. 目标（边界 B 最终态）

- 系统只剩一条判恶路径：AI 用数据工具调查 + AI 判恶 + 证据门槛 + 发布校验。
- `Fact`/`Finding`/`Relation`/`EvidenceGap`/`EvidenceRole`/`Hypothesis`/`analyzer`/确定性 `verdict` 全部移除。
- 报告契约、交接契约、展示层全部对齐新活动模型。

## 3. 完整影响面

### 3.1 彻底删除（纯确定性）

- `judgment/domain/analyzers.py`、`verdict.py`、`scenarios.py`
- `judgment/application/planner.py` 的 `DeterministicPlanner`
- `judgment/application/state.py`、`orchestration.py`
- `judgment/application/policy.py` 的确定性校验
- `judgment/adapters/tools.py`（`ToolRegistry` 证据/分析工具）
- `data_foundation/adapters/repository.py`（`FixtureEvidenceRepository`/`JsonlEventRepository`）
- `data_foundation/ports/evidence_query.py`
- `contracts/evidence.py` 的 `Evidence`/`EvidenceBundle`/`Coverage`；`contracts/investigation.py` 的 `Fact`/`Finding`/`Relation`
- `cases/` 18 个 golden case

### 3.2 重写（深度耦合确定性字段）

- `judgment/domain/models.py`：`InvestigationState` 大瘦身——删 facts/findings/relations/evidence/evidence_gaps/analysis_obligations/coverage/hypotheses/evidence_roles/interpretations/repair_actions/tool_scores/evidence_packs/planner_decisions，只保留 case 锚点 + scope + budget + tool_ledger + verdict。
- `case_management/application/intake.py`：`initialize_state` 不再初始化确定性字段。
- `case_management/application/graph.py`：`CaseGraph` 的研判子图只走数据工具路径。
- `case_management/application/read_model.py`、`contract_builders.py`、`reporting.py`、`data_readiness.py`
- `judgment/application/reporting.py`：报告契约
- `response_advisory/*`：交接契约
- `presentation/*`、`bootstrap/demo.py`、`demo_runtime.py`、`cli.py`
- 大量测试

### 3.3 保留

`data_foundation` 新活动模型全套、`InvestigationToolGateway`、`StructuredDataToolPlanner`、`evidence_gate.py`、`StructuredReportComposer`（改契约）。

## 4. 已确认决策

### 4.1 demo 页 L0~L3 对照

改为**数据就绪度展示**：每个 profile 直接由 `DataProfile` 派生"能查到哪些数据、能支撑哪些调查问题"，不跑调查；AI 实时调查由用户点按钮触发。保留 feature 07 的"数据重要性"叙事，去掉确定性四列结论。

### 4.2 回归策略

18 个 golden case 删除，回归改为：

- 新活动模型的确定性单测（活动能正确入库/查询）；
- AI 判恶路径的集成测试；
- 真实模型冒烟。

判恶正确性不再靠硬编码断言，而靠证据门槛 + 发布校验 + 冒烟。

## 5. 分阶段策略（无法安全地"一次性"完成）

即使目标是 B，也必须分阶段，每阶段系统可运行：

1. **阶段 1（对齐契约，解决两个瑕疵）**：报告契约 + 交接契约对齐新模型，`build_judgment_result` 从 `tool_ledger` harvest。此时确定性路径仍在，但 AI 路径已完整可用。
2. **阶段 2（退役确定性判恶）**：删 `analyzers`/`verdict`/`scenarios`/`DeterministicPlanner`/`ToolRegistry`/golden case，重写 `InvestigationState`/`initialize_state`/`CaseGraph`。
3. **阶段 3（重建 demo 对照 + 回归）**：按 4.1、4.2 的决策重建 demo 页与测试基线。

## 6. 验收

- 系统只剩 AI 判恶路径，`Fact/Finding/Relation` 全仓零引用；
- 在线真实 LLM 跑通：报告引用新模型、处置建议能产出带证据的动作；
- demo 页按决策正常展示；全量测试绿。
