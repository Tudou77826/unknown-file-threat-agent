# Session 上下文交接：Linux 未知文件威胁研判 Agent（截至 P2.5）

## 1. 工作目录

项目根目录：

`D:\My Files\研一\huawei\Anthropic-Cybersecurity-Skills-main\unknown-file-threat-agent`

旧 MVP 位于 `legacy_mvp/`，已经隔离，当前代码不导入它。不要在 V1/P2.5 验收完成前混回旧实现。

## 2. 用户最终目标

对 Linux 未知文件分析来源、执行、运行行为和实际影响，还原有证据支撑的攻击路径，识别后门/C2、数据窃取、勒索和其他攻击。Agent 必须能根据当前证据主动发现 EvidenceGap、调用查询或 Analyzer、在证据指向其他主机时受控申请扩大 Scope，并在反证和数据缺失下输出可信的案件结论。

用户明确要求：不能把必须确定化的安全研判规则交给 LLM；也不希望 Agent 只是空架子。因此采用“LLM 调查规划 + 确定性证据/分析/验证 + Skill 调查知识”的混合架构。

## 3. 当前已完成阶段

- P0：四类结构化动作、动态 Tool Catalog、Schema/引用/Scope/重复/预算校验、一次模型动作修复。
- P1：C2 完整闭环，原始 JSONL 事件、调查级 Tool、AnalysisObligation、Fact/Finding/Relation、恶意/良性/证据不足 Case。
- P2.0：Evidence Role、Interpretation、Coverage 语义、Analyzer 输入隔离、PlannerDecision、Verdict Validator 和 evaluation。
- P2.1：文件来源调查与受控场景激活。
- P2.2：数据窃取完整闭环，HTTPS、DNS、合法备份反证和四类 Case。
- P2.3：Linux 勒索闭环，影响、加密、恢复破坏、勒索标记、合法批任务反证和四类 Case。
- P2.4：受控跨主机 ScopeExpansion、跨主机 Tool/Analyzer、共享 C2 不等于传播、批准部署反证和四类 Case。
- P2.5：ToolScore、EvidencePack、RepairAction、Verdict 修复、LLM 状态裁剪、预算收敛、Linux Skill 知识扩充和专项场景路由。

## 4. P2.5 本次新增或修改

### 数据结构

`threat_agent/models.py` 增加：

- `ToolScore`
- `EvidencePack`
- `RepairAction`
- Repair/Verdict Repair 预算
- `InvestigationState.tool_scores/evidence_packs/repair_actions`

### 编排

新增 `threat_agent/orchestration.py`：

- 多因素工具评分；
- EvidenceBundle 到 EvidencePack 的封装；
- 类型化 RepairAction；
- Verdict 失败后的限次补证计划；
- 只应用指定 Repair ID，防止结论修复误拿历史无关待办。

### Planner 与 Engine

- `planner.py` 只向模型暴露相关 Evidence、最近 20 次 ToolCall、最近 8 个 EvidencePack、待处理 Repair 和 Top-12 Tool。
- Tool 分数是建议，Tool 是否可见和可执行仍由 Registry/Policy 决定。
- ScopeRequest 中无效 Evidence 引用和抽象数据域会本地规范化。
- `engine.py` 记录每轮 ToolScore，构建 EvidencePack，处理空结果替代源、非法动作、Scope 拒绝、异常、Verdict 修复和预算收敛。
- 专项 Case 的初始路由不再强制跑无关 C2 Gap，但后续有证据时仍可激活受控 C2 模板。

### Skill

`investigation_skills/linux-unknown-file/SKILL.md` 增加 Linux 执行、认证、持久化、文件、网络、容器/Kubernetes 数据源清单，数据缺失时的替代源策略、EvidencePack/Repair 纪律和停止条件。参考了仓库中的 Linux 系统工件、audit、持久化、Docker、Kubernetes、DNS 窃密和 IR playbook 内容；未迁移其中命令执行或处置动作。

## 5. 验收结果（2026-08-06）

- `python -m pytest -q`：59 passed。
- 全部 18 个 `cases/*/expected.json`：18 PASS、0 FAIL。
- 覆盖 C2、文件来源、窃密、勒索、跨主机的恶意、良性和证据不足对照。
- 所有 Relation/攻击路径边均能回溯到存在的 Evidence ID。
- 真实 `zai-org/GLM-5.2` + DeepAgents 完整运行 `ransomware_malicious`：
  - 17 iterations
  - 16 ToolCalls
  - 9 EvidencePacks
  - 0 denied、0 repaired、0 fallback
  - Verdict：`confirmed_malicious / ransomware`
  - Verdict Validator：PASS
  - unsupported path edges：0
  - 耗时约 352.5 秒，主要是模型 API 单轮延迟。

真实模型选择顺序合理：执行确认 → 批量文件影响 → 内容/熵变化 → 重命名模式 → 合法基线反证 → 破坏命令/备份破坏 → 勒索信 → 服务中断；就绪 Analyzer 由 Engine 自动插入。

## 6. 关键设计边界，不要回退

1. 告警/Detail 是 Claim 或初始上下文，不直接等于安全事实。
2. Evidence Tool 只查询事件与 Coverage，不返回预写攻击结论。
3. LLM 不创建确认 Fact/Finding，不批准 Scope，不直接决定最终 Verdict。
4. Analyzer 只能消费 AnalysisRequest 指定的 Evidence ID。
5. 每条攻击路径 Relation 必须引用存在 Evidence，端点 Entity 必须存在。
6. 恶意链必须检查相应反证；`unavailable` 不是阴性证据。
7. 共享 IP/C2 只能形成跨主机线索，不能单独证明横向传播。
8. Scope 扩大必须由已有 Evidence 直接命名候选主机并受审批/预算限制。
9. Skill 是调查知识，不是 Tool；Tool 是可执行能力，Analyzer 是注册为 Analysis Tool 的确定性程序。
10. 不向模型暴露本地文件系统或 Shell Tool。

## 7. 主要文件入口

- `README.md`：阶段能力和运行命令。
- `docs/CURRENT_PROJECT_COMPLETE_GUIDE.md`：完整架构与实现讲解。
- `threat_agent/cli.py`：命令行入口和 `run_case`。
- `threat_agent/engine.py`：调查主循环。
- `threat_agent/planner.py`：Deterministic/DeepAgents Planner。
- `threat_agent/models.py`：状态和动作 Schema。
- `threat_agent/tools.py`：Tool Registry、Catalog、查询定义。
- `threat_agent/analyzers.py`：确定性安全分析。
- `threat_agent/repository.py`：JSONL 查询与 Coverage。
- `threat_agent/scenarios.py`：受控调查场景。
- `threat_agent/orchestration.py`：P2.5 编排对象。
- `threat_agent/verdict.py`：结论和路径验证。
- `investigation_skills/linux-unknown-file/SKILL.md`：调查知识。

## 8. 运行命令

在项目根目录：

```powershell
# 测试
.\.venv\Scripts\python.exe -m pytest -q

# 离线确定性 Case
.\.venv\Scripts\python.exe -m threat_agent.cli --case cases\c2_benign --mode deterministic --output outputs\c2_benign

# 真实模型 Case
.\.venv\Scripts\python.exe -m threat_agent.cli --case cases\ransomware_malicious --mode deepagents --output outputs\ransomware_malicious_agent
```

模型配置在 `.env` / `threat_agent/model_config.py`。不要把 API Key 写入文档、测试输出或提交记录。当前用户选择模型为 `zai-org/GLM-5.2`，走 OpenAI-compatible 接口。

## 9. 当前未实现或仅为模拟的部分

- 真实生产数据适配器：EDR、auditd、eBPF、DNS/流量、CMDB、Kubernetes、对象存储或数据湖。
- 实际人工 Scope 审批工作流；当前只有策略与状态模型。
- 静态 ELF/脚本分析、YARA、反汇编、沙箱、内存取证。
- 容器/Kubernetes 专用 Tool/Analyzer；目前仅迁移了调查知识清单。
- 数据库持久化、服务 API、任务队列、并发、鉴权、租户隔离、审计日志和部署。
- 自动响应/隔离/封禁；当前严格只读。
- 大规模真实数据集上的阈值校准、准确率、召回率、成本和延迟评估。
- 专门的跨主机传播 Verdict 枚举；当前恶意跨主机 Case 使用 `other`。
- RepairAction 目前以规则型补证为主，尚无复杂多候选修复计划搜索。

## 10. 当前难点

- LLM 自主性与确定性安全边界：既要让模型选择调查方向，又不能让它编造事实或越过规则门槛。
- Coverage 与阴性证据：完整查询无结果和数据源不可用必须严格区分。
- 多场景状态膨胀：需要场景路由和切片，避免模型在专项 Case 中机械跑完全部 C2 清单。
- 证据链一致性：Entity、Evidence、Fact/Finding、Relation、Verdict 引用需要全程可验证。
- 跨主机控制：发现线索、批准扩域、目标侧查询必须分阶段，防止模型无限扩散。
- 模型延迟：完整 GLM Case 约六分钟，离线确定性 Case 用于快速回归，真实模型用于规划质量抽检。

## 11. 推荐下一阶段

优先做“生产数据接入最小切片”，而不是继续堆规则：

1. 定义 Repository Adapter 接口和统一事件映射规范。
2. 选择一套真实可获得的数据源，先接进程、文件、网络三个域。
3. 用脱敏真实 Case 回放，统计 Tool 命中率、Coverage、Verdict 准确性和 LLM 调用成本。
4. 增加服务化 Case Store 和可恢复状态持久化。
5. 再根据误差分析扩展容器/Kubernetes、静态样本或新的攻击场景。

继续工作前先运行 59 项测试；任何修改都应同时保留恶意、良性、证据不足三类对照，不能只让恶意 Case 通过。
