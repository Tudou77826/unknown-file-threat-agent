# 模型迁移实现计划

目标：退役确定性判恶，统一到 AI 判恶 + 新活动模型。分三个阶段，每阶段结束系统可运行、测试绿。

## 阶段 1：对齐契约（解决两个瑕疵，确定性路径仍保留）

1. 改 `contracts/investigation.py`：`JudgmentResult` 删 `facts`/`findings`/`relations`。
2. 改 `contracts/operations.py`：`InvestigationReport` 删 `attack_path`/`key_facts`/`key_findings`，新增 `supporting_evidence_refs` 语义收紧；`key_findings` 的展示语义改由 `current_situation`/`counter_evidence` 承载。
3. 改 `contract_builders.py`：`build_judgment_result` 从 `tool_ledger` harvest `evidence_refs`。
4. 改 `response_advisory`（planner/policy/reference_context）：不再读 `judgment.facts/findings`。
5. 改 `reporting.py`（`ReportDraft`/`_publish`/`validate`/`_sanitize_report`）：对齐新契约。
6. 改展示层 `presentation/*`、`demo.py`：`key_findings` → 叙事 + 证据引用计数。

**验收**：真实 LLM 跑通，处置建议能产出带 `judgment_refs` 的动作，报告不再有"引用不存在 fact/finding"的大串剔除。

## 阶段 2：退役确定性判恶

1. 删 `judgment/domain/analyzers.py`/`verdict.py`/`scenarios.py`。
2. 删 `judgment/application/planner.py` 的 `DeterministicPlanner`、`state.py`、`orchestration.py`、`policy.py` 的确定性校验、`adapters/tools.py`（`ToolRegistry`）。
3. 删 `data_foundation/adapters/repository.py`、`data_foundation/ports/evidence_query.py`。
4. 删 `contracts/evidence.py` 的 `Evidence`/`EvidenceBundle`/`Coverage`、`contracts/investigation.py` 的 `Fact`/`Finding`/`Relation`。
5. 重写 `judgment/domain/models.py` 的 `InvestigationState`（瘦身）。
6. 重写 `case_management/application/intake.py`、`graph.py`。
7. 删 `cases/` 18 个 golden case。

**验收**：全仓 `Fact/Finding/Relation` 零引用，系统只走数据工具 + AI 判恶。

## 阶段 3：重建 demo 对照 + 回归

1. demo 页 L0~L3 改为数据就绪度展示（由 `DataProfile` 派生，不跑调查）。
2. 回归测试改为：新活动模型单测 + AI 路径集成测试 + 真实模型冒烟。
3. 删掉依赖 18 case 的测试。

**验收**：demo 页正常展示就绪度 + 可点按钮跑 AI；全量测试绿；真实模型冒烟通过。
