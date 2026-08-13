# Evidence-Gated AI Judgment — Design

## 1. 现状

项目里"AI 查案"有两条实现路径，真实架构只有一条：

| | demo 页路径（真实） | CLI `--mode llm` 路径（遗留） |
|---|---|---|
| 数据来源 | 新活动模型（`NormalizedActivity`，SQLite） | 旧证据模型（`evidence.json` / `EvidenceGap`） |
| AI 工具 | 4 个数据工具 + 2 个流程动作 | 9 个"按领域证据"工具 |
| 最终"坏不坏"由谁判断 | **AI**（写报告、下 `verdict`） | 写死的 if-else 规则（`verdict.py`） |
| 代码职责 | 发布前纠错（引用/Scope/候选关系） | 代码替 AI 判恶 |

feature 08 的设计已明确结论（`08-investigation-platform-foundation/design.md` 第 195 行）：**按场景命名的查询和分析工具只用于离线确定性测试，不作为首版在线 LLM Tool Catalog**。即：demo 路 = 在线 AI 研判的唯一正确实现；CLI 的证据工具 LLM 模式 = 遗留，应予清理。

AI 判恶发生在 demo 路的 `StructuredReportComposer`：AI 通过 `json_mode` 输出 `ReportDraft`（含 `verdict`），现有唯一把关是 `validate()`（检查引用/Scope/候选关系），**不检查"证据够不够判恶意"**。

证据门槛的雏形已存在于 `judgment/domain/verdict.py` 的 `validate_verdict`，但绑定旧证据模型（`fact_type`/`finding_type`），只在遗留路径被调用。本 Feature 把"门槛"思想搬到新活动模型之上。

## 2. 目标

1. AI 自由调工具、自由填参数，发挥其智能。
2. AI 自行判断"证据够不够 + 坏不坏"，不降级为代码 if-else 判恶（避免检出率低）。
3. 加一道**证据门槛守卫**：AI 下"恶意"结论必须凑齐程序化定义的证据要求；凑不齐则降级为"置信度 + 进一步确认建议"，不许硬判恶意。

一句话：**AI 是侦查员 + 判断官；代码是把门的，只挡"证据不够还要判恶意"，不替 AI 下结论。**

## 3. 做法

### 3.1 证据门槛守卫（核心）

新增 `EvidenceGate`，规则表形如（每种威胁类型 → 判"确认恶意"至少覆盖的证据能力）：

| 威胁类型 | 判恶意至少覆盖 |
|---|---|
| `backdoor_c2` | 文件执行 + 外联 +（持久化 或 远程命令） |
| `data_exfiltration` | 敏感访问 + 打包 + 外传 + 无合法基线反证 |
| `ransomware` | 大范围文件影响 + 加密变换 + 破坏性影响 |
| `lateral` | 文件转移 + 目标执行 |

"证据能力"从本次运行的 `activities` 里确定性判定（例：`process_exec` → 覆盖"执行"；`network_connection` → 覆盖"外联"）。判定是纯函数，只回答"覆盖了哪些能力"，不产出"坏不坏"结论。

发布流程：

```
AI 输出 ReportDraft(verdict)
  → EvidenceGate：verdict 是"恶意"级别？
      → 是 → 引用证据凑齐该威胁类型要求？
          → 凑齐 → 放行
          → 没凑齐 → 降级 verdict + 追加"证据不足，建议确认 X/Y"
      → 否（良性/证据不足）→ 放行
  → validate() 做引用/Scope 纠错
```

**代码只降级、从不升级**：AI 说良性，代码不改；AI 说恶意但证据不够，代码压回"可疑/证据不足 + 处置建议"。判断权在 AI，代码只把门。

### 3.2 工具按领域拆分

现状 demo 路是 1 个 `query_activities`，`activity_type` 参数是判别联合（8 种类型塞一个工具）。拆成独立工具：`query_process_activities` / `query_network_activities` / `query_file_activities` / …。

每个工具名即查询领域，`activity_type` 由工具名固定，工具的**参数 Schema 只暴露该领域自己的字段和过滤器**。效果：领域由工具本身决定，AI 看到的工具就是它能查的范围——其他领域的字段根本不在该工具 Schema 里，因此不存在"跨领域调用"或"跨域被拒"这种防御概念。

Gateway 的强类型路由只负责把领域工具接到对应的活动查询端口，不做"校验 AI 是否填错领域"的额外逻辑。

### 3.3 报告生成超时

demo 路调查循环正常，但 `StructuredReportComposer` 用 `json_mode` 输出大号 `ReportDraft` 时 60s 超时。做法方向（先定位再定）：调大超时 + 评估报告拆成多步生成，避免单次大 JSON。

## 4. 已确认决策

1. **CLI 证据路径**：删除 `--mode llm`，CLI 只保留 `deterministic`（离线测试）。在线 AI 调查唯一入口是网页 demo。
2. **工具粒度**：查询工具按领域拆成独立工具（`query_process_activities` / `query_network_activities` / `query_file_activities` / …），不再用一个 `query_activities` + `activity_type` 参数承载全部类型。

> 历史：错误提交 `3bc0d07` 已 revert（`ca1f51d`），该错误设计不再占用 09 序号。
