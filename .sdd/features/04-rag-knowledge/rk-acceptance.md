# RK-01～RK-09 验收记录

- 日期：2026-09-14
- 依据：`rag-adapter-requirements-design.md` 第 9 节验收条件
- 验收载体：行为可控的参考适配器（RK-09，内存固定语料），未接入真实 RAG 供应方
- 结果：**RK-01～RK-09 全部通过**；全仓 201 项测试通过（exit 0），含架构依赖测试 16 项

## 验收执行

| 编号 | 验收测试（`tests/test_rk_acceptance.py`） | 结果 |
|---|---|---|
| RK-01 | `test_rk_01_business_surface_has_no_supplier_or_authorization_fields`、`test_rk_01_authorization_is_bound_by_the_framework_only` | 通过 |
| RK-02 | `test_rk_02_baseline_always_runs_and_three_entries_answer`、`test_rk_02_baseline_degrades_explicitly_without_blocking` | 通过 |
| RK-03 | `test_rk_03_disposal_presents_all_sources_and_keeps_constraints` | 通过 |
| RK-04 | `test_rk_04_supplier_swap_via_config_only` | 通过 |
| RK-05 | `test_rk_05_traceable_references_and_scores_stay_diagnostic` | 通过 |
| RK-06 | `test_rk_06_tenant_restricted_item_never_reaches_other_tenants`、`test_rk_06_injected_knowledge_cannot_become_evidence` | 通过 |
| RK-07 | `test_rk_07_failure_states_distinguishable`（参数化 5 态）、`test_rk_07_any_knowledge_failure_never_blocks_the_core_flow` | 通过 |
| RK-08 | `test_rk_08_supplier_selection_is_config_only` | 通过 |
| RK-09 | `test_rk_09_reference_adapter_covers_all_simulated_behaviors` | 通过 |

支撑测试：`tests/test_knowledge_capability.py`（24 项，底座）、`tests/test_knowledge_investigation.py`（10 项，研判侧）、`tests/test_knowledge_response.py`（6 项，处置侧）、`tests/test_architecture_dependencies.py`（16 项，分层与授权绑定规则）。

逐项明细见同目录 `rk-acceptance-run.txt`。复跑命令：

```
pytest tests/test_rk_acceptance.py -v
pytest tests/            # 全量回归
```

## 落地结构（四步计划执行结果）

1. **知识能力底座**：`contracts/knowledge.py` 业务契约（场景/意图/最小化上下文 → 标准化知识条目）；`knowledge/application/capability.py` 场景服务（查什么、按源合并、失败隔离、类别级限制）；`knowledge/ports/supplier_retrieval.py` 供应方形状内部 Port；`adapters/reference_retriever.py` 参考适配器 + `adapters/null_supplier.py`；`shared/execution.py` 授权执行上下文（一次绑定、全程继承）；`KnowledgeSettings` 配置（RK-08 首期形态）。
2. **研判侧接入**：`judgment/application/graph.py` 基线检索固定节点（finish 路由必经）；`judgment/adapters/knowledge_tools.py` 三个拆分工具（查 ATT&CK / 解释告警日志字段 / 查研判经验）；结案咨询记录进 `InvestigationToolLedger.knowledge_consultations`；基线指引进 `report_context` 的 `knowledge_guidance` 段。
3. **处置侧接入**：`response_advisory/application/graph.py` 固定节点改走能力层场景服务；合并并列呈现（不丢弃、按相关性排序、冲突并列标注、推荐至多附理由）；`ResponseAction.knowledge_refs` 承载可追溯引用；旧契约（KnowledgeQuery/KnowledgeResult/KnowledgeCitation）与旧 Port、旧 Null Adapter 已删除，Port 依赖清零。
4. **贯通验收**：知识咨询事件接入既有 OperationalEvent/AuditEvent 通道（action=`knowledge_consulted`，resource_ref=`query_id`）；供应方明细留适配层 `call_log` 凭 query_id 关联；RK-04 换档演练（standard→alternate 仅配置切换，业务面零改动）。

## 实施与设计的偏差说明

1. **查询意图细分**：第 4/5 节的意图在"调查指引、告警/日志含义解释、处置政策参考"之外增加 `attack_technique_lookup`、`judgment_experience_lookup` 两个细分意图，作为三个拆分工具在同一场景服务上的入口；基线检索仍用 `investigation_guidance`。意图仍是业务语义，Agent 不感知知识源。
2. **处置引用字段迁移**：`ResponseAction.knowledge_citations`（旧占位契约 KnowledgeCitation 列表）迁移为 `knowledge_refs: list[str]`（`knowledge_id@version#chunk_id`）。
3. **基线指引进入研判上下文**：`report_context` 增加 `knowledge_guidance` 段，并附"不得作为支撑证据引用"指令；事实隔离由报告接地校验强制执行（引用知识 ID 一律 `unknown_evidence_ref` 拒绝）。
4. **参考语料含验收夹具**：两个提示注入样本（研判侧 `ke-judgment-poison-001`、处置侧 `ke-sop-poison-001`）与一个租户受限条目（`ke-resp-tenantb-001`，仅 tenant-b 可见），用于 RK-06 验收。
5. **审计关联键**：结案咨询记录 `KnowledgeConsultationRecord` 增加 `query_id` 字段，与适配层明细及 AuditEvent 的 resource_ref 对齐（设计 §7-4）。

## 未包含（按设计另立实施需求）

真实供应方接入、管理面入口（导入/调参/评测/重建的界面与驱动逻辑）、case_memory 域、知识质量评测。
