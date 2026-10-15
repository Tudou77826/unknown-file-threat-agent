# 真实源端接入 — 缺口清单与实施指引

面向接入实现方：当前代码已交付数据访问边界，本文列出接入真实态势感知数据源前剩余的缺口、每项的落位与验证方式，以及需要按源端实际情况决定的开放点。接口与数据约定见 [design.md](design.md)。

## 1. 已交付基线

- 契约：`contracts/situational_awareness.py`，11 个类型，Scope 不变量在模型层强制。
- 端口：`data_foundation/ports/situational_awareness.py`，`SituationalAwarenessDataPort` 复用 `InvestigationDataPort`。
- 适配器：`data_foundation/adapters/situational_awareness.py`，负责组合、租户/主机出站校验、三态错误语义（空结果 / 不支持 / 失败）。
- 注入式数据面：`assemble_investigation_run`、`build_run_service`、`AlertExecution`、`AlertCheckpointAccess` 与审批、调试服务均接受注入的 `InvestigationDataPort`；注入后不打开本地活动库。
- 测试：`tests/test_situational_awareness_adapter.py` 与 `tests/test_situational_awareness_bootstrap.py`，21 个用例，全量回归通过。

AI 研判层现有 14 个工具（8 个活动查询、3 个实体与证据工具、3 个知识工具）全部经 `InvestigationDataPort` 取数，接入真实源后自动获得真实数据，无需改动。

## 2. 缺口清单（按依赖顺序）

### 缺口 1：真实源端 handler 与代码落位

实现源数据库读取与 IR 调用的 handler，包含字段映射与必要关联。

落位约定：在 `data_foundation/adapters/situational_awareness/` 子包内实现，现有单文件防护壳改为子包中的 `adapter.py`，由 `__init__.py` 再导出保持导入路径不变。建议结构：

```
data_foundation/adapters/situational_awareness/
├── __init__.py      # 再导出 SituationalAwarenessDataAdapter 与组装函数
├── adapter.py       # 现有防护壳：组合、出站校验、错误语义（不再增长）
├── settings.py      # 源端连接配置
├── assembly.py      # assemble(settings) -> InvestigationDataPort，唯一源端组装点
├── db/              # 源数据库读取，一个查询域一个模块，字段映射在各模块内
└── ir/              # IR 客户端与响应映射
```

分工边界：handler 只负责读取与转换；出站校验（租户/主机一致性、哈希与资产回执核对）与三态错误语义由 `adapter.py` 统一执行，handler 不必重复实现。字段映射规则（文件事件中操作进程哈希与目标文件哈希分列、进程关联歧义用候选关系表达）见 design.md 第 3 节。

当源端能力规模或部署形态超出单一数据边界时（多源端产品、独立进程部署），可将子包整体提升为独立纵向包；端口仍留在 `data_foundation/ports/`，消费方依赖不变。

### 缺口 2：serve 桥接

`bootstrap/demo.py` 的 `--serve` 分支目前调用 `build_run_service(settings, project_root=PROJECT_ROOT)` 未传数据面，回落本地 SQLite。接入后改为传入缺口 1 的 `assemble(settings)` 产物。完成后，工作台（`uv run threat-agent-demo --serve` → `http://127.0.0.1:8000/workbench`）的手工告警即走真实源数据。

### 缺口 3：AI 工具层暴露（4 个新工具）

新增 4 个查询已有端口方法，但未进入 AI 工具目录（`judgment/adapters/investigation_tools.py` 的 `_DOMAIN_TOOLS` 与工具清单），AI 目前无法调用。方案：

| 工具 | 输入 | 返回投影 | 证据地位 |
|---|---|---|---|
| `query_file_reputation` | 文件哈希 | 查询名单、命中列表（名单名/有效期/名单范围/源记录 ID）、源端备注 | 可引用证据，须标注来源性质；确认恶意仍需行为证据支撑 |
| `get_asset_info` | 主机引用 | 资产属性键值、来源系统、更新时间 | 上下文参考，不构成行为证据 |
| `query_alerts` | 主机引用 + 时间窗 + 分页（过滤字段见开放点 1） | 源告警 ID、检测时间、文件路径与哈希、进程线索、原文引用 | 线索，可引用（引用源系统告警记录这一事实） |
| `query_source_assessments` | 实体引用 + 时间窗 + 分页 | 产生方式（人工/规则/模型）、结论/评分、记录类型、依据引用 | 外部结论（防锚定要求见开放点 2） |

配套工作：

1. `InvestigationToolLedger` 新增收容区：告警、信誉、源端研判各一节；资产信息作为上下文不进账本。
2. 报告校验器扩展：上述引用需带 `source_system` 与 `source_record_id`（契约已保留），且必须能在账本中找到。
3. `investigation_skills/linux-unknown-file/SKILL.md` 三处接入：调查顺序开头（资产上下文 + 关联告警）、文件确权阶段（信誉分流：已知良性/已知恶意快速通道，未知走完整调查）、假设形成阶段（源端研判参考与纪律）。按项目规则，修改 SKILL.md 后必须同步验证 Planner 与端到端 Case。

已定决策：`query_extension` 暂不进入工具目录，待真实源端确认有扩展遥测再评估。

### 缺口 4（可选后续）：告警 intake 连接器

当前告警由人工在工作台粘贴 JSON 建案。可选增加连接器：定时调用 `query_alerts` 拉取新告警并自动建运行。依赖缺口 1、3 完成。

### 缺口 5（已知限制）：数据画像与注入式适配器不组合

`assemble_investigation_run` 在注入适配器时拒绝 `visible_sources` 参数，而 `SituationalAwarenessDataAdapter` 尚无该能力——Feature 07 的数据画像对照实验在注入式数据面暂不可用。需要时给该适配器补 `visible_sources` 支持，或明确宣布画像机制仅属本地演示路径。

## 3. 开放点（按源端实际情况决定）

1. **告警过滤字段**：`AlertQuery` 现仅有范围/时间/分页。按源端实际能力在以下方案中选择：补 `file_hash` + `entity_refs` 过滤（定向查"该哈希/实体的相关告警"，源端不能下推时可在模块内本地过滤）；仅补 `file_hash`；首版不扩。这是 4 个工具中唯一可能需要调整契约的点。
2. **源端研判的防锚定强度**：核心风险是 AI 照抄源端结论、放弃本地证据链。备选：投影降权（产生方式与"外部结论需独立验证"标注置顶）+ SKILL 纪律（推荐基线）；硬隔离（不进报告证据引用区，校验器拒绝其作为结论依据）；分级披露（人工结论全文，规则/模型结论只给方向与评分）。由接入方按研判文化定夺。

## 4. 验收门槛

承接 design.md 第 4 节，并按缺口扩展：

1. 源端样本验证：查询、字段转换与错误语义（空 / 不支持 / 失败三态区分）。
2. 真实告警端到端：工作台手工告警 → AI 调查取到真实活动数据 → 报告证据引用可回溯到源端原始记录。
3. 换源不变性：替换 db/ir 实现后，同一输入保持相同输出含义（现有测试已锁定该承诺，接入后补真实源版本）。
4. Planner 验证：缺口 3 的工具接入后，端到端 Case 全绿，确认 AI 在合适时机调用新工具且正确解读结果。
