# Evidence-Gated AI Judgment — Implementation Plan

每条步骤以"改动 + 验收"闭环。整体目标：删掉 CLI 的 LLM 证据路径、把数据工具按领域拆开、加证据门槛守卫、修报告超时；demo 路成为在线 AI 研判的唯一实现，确定性路径只服务离线测试。

## 步骤 1：删除 CLI `--mode llm`

**改动**：`src/threat_agent/bootstrap/cli.py`

- `--mode` 只保留 `deterministic`，移除 `llm` / `deepagents`；
- `run_platform_case()` 移除 LLM 分支（`StructuredJudgmentPlanner` / `StructuredResponsePlanner` / `build_judgment_model` / `build_response_model` 相关接线）；
- 清理不再使用的 import。

**验收**：`python -m threat_agent.bootstrap.cli --case cases/c2_malicious`（默认 deterministic）正常输出；`--mode llm` 报参数错误；`pytest -q` 全绿。

## 步骤 2：数据查询工具按领域拆分

**改动**：

- `data_tool_planner.py` 的 `investigation_tools()`：把 1 个 `query_activities` 拆成按领域的独立工具（`query_process_activities` / `query_network_activities` / `query_socket_activities` / `query_file_activities` / `query_service_activities` / `query_package_activities` / `query_asset_activities`），各自 `activity_type` 固定、参数去掉 `activity_type`；
- `investigation_tools.py` 的 `InvestigationToolGateway`：`tool_names` 扩展、`invoke()` 按工具名路由到对应 `activity_type` 再复用现有 `query_activities` 逻辑；
- `contracts/investigation_tools.py`：`DataToolRequest.tool_name`、`InvestigationToolTrace.tool_name` 的 `Literal` 同步扩展。

**验收**：单测覆盖"每个领域工具的 Schema 只含本领域字段/过滤器、`activity_type` 由工具名固定"；`test_llm_investigation_tools.py` 适配后全绿；demo 页工具 Schema 展示拆开后的独立工具。

## 步骤 3：证据门槛守卫

**改动**：新增 `judgment/application/evidence_gate.py`

- `EvidenceGate`：规则表（威胁类型 → 判恶意至少覆盖的证据能力），从本次运行 `activities` 纯函数判定覆盖了哪些能力；
- 接入 `StructuredReportComposer` 的发布链路：AI 产出 `ReportDraft` 后，若 verdict 是"恶意"级别但证据能力不满足对应威胁类型要求，则**降级** verdict 等级 + 追加"证据不足，建议确认 X/Y" 的 limitation；
- 代码只降级、从不升级；良性/证据不足结论直接放行。

**验收**：单测覆盖"证据够 → 放行""证据不够 → 降级且不动良性结论""降级信息可追溯"；确定性路径行为不变。

## 步骤 4：修复报告生成超时

**改动**：

- 先定位：`StructuredReportComposer` 用 `json_mode` 输出大号 `ReportDraft`，单次 60s 超时（`.env` 的 `*_MODEL_TIMEOUT_SECONDS=60`）；
- 方案 A：调大报告阶段超时上限；
- 方案 B：报告拆成"结论 + 分项"多步生成，避免单次大 JSON；
- 先做 A（最小改动）验证，仍超时再做 B。

**验收**：demo 页 "启动 AI 全流程调查" 完整跑通（调查循环 + 报告 + 处置），不再 `APITimeoutError`。

## 步骤 5：全量回归 + 真实模型复验

**改动**：无新代码，验证收口。

**验收**：`pytest -q` 全绿；demo 页对 `c2-malicious-reference` 与 `c2-benign-reference` 各跑一次真实 LLM 调查，观察工具调用是否合理、结论是否被证据门槛正确约束、是否收敛。
