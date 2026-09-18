# Unknown-File Threat Agent

面向 Linux 未知文件告警的 AI 安全研判系统：把规范化安全活动、实体关系和受控原始记录
交给受边界约束的调查工具，由模型完成证据门控研判与处置建议；案件图负责生命周期、
审批中断与 Checkpoint 回溯，运行工作台提供使用面（建案、运行视图、审批台、报告审阅）
与调测面（三栏轨迹、时间旅行、知识面板）。

核心原则：**证据接地**（结论只能引用授权查询返回的证据）、**边界纪律**（跨主机/越权
查询被确定性拦截并如实记录）、**数据不出域**（全组件本地自托管，无云依赖）。

## 能力总览

| 能力 | 说明 |
|---|---|
| 证据化研判 | create_agent + middleware 正式循环：取证 → 证据门 → 报告接地校验 → 兜底降级 |
| 处置建议 | 独立建议图：动作分级、审批等级、missing_context 与 residual_risk |
| 运行工作台 | 案件列表、SSE 实时运行视图、内联审批卡、知识命中面板、Checkpoint 重放 |
| 知识能力 | 供应方无关 RAG 端口；`attack` 档接入 MITRE ATT&CK v19.2 全量 697 条（离线词法检索） |
| 可观测 | Langfuse 旁路 sink（缺包自动降级，不阻断业务） |
| 评测内核 | `agent_eval`：Case/RunRecord/多维 Score 契约、并发 Runner、pass^k 聚合（业务适配器待接） |

## 安装与验证

要求 Python 3.10+，使用 uv 管理锁定依赖。

~~~powershell
uv sync --extra dev --locked
uv run pytest -q
~~~

## 配置

在项目根目录 `.env` 中配置模型服务（只写与默认值的差异，完整键见 `.env.example`）：

~~~text
THREAT_AGENT_API_KEY=<key>
THREAT_AGENT_API_BASE=<OpenAI 兼容端点或 Anthropic Messages 端点>
THREAT_AGENT_MODEL_PROVIDER=openai | anthropic
MODEL_NAME=<model>
KNOWLEDGE_ADAPTER=attack          # null | reference | attack
~~~

## ATT&CK 知识语料

`KNOWLEDGE_ADAPTER=attack` 时，`attack_technique` 知识源由离线构建的真实语料服务
（仓库已内置 `corpora/attack_technique.jsonl`，v19.2 全量 697 条，含中文摘要与关键词，
运行时零网络零模型调用）。数据更新或重建：

~~~powershell
uv run python scripts/build_attack_corpus.py            # 全量构建（LLM 中文化，缓存幂等）
uv run python scripts/build_attack_corpus.py --limit 20 # 冒烟构建
uv run python scripts/build_attack_corpus.py --refresh-llm  # 忽略缓存整表重新生成
~~~

MITRE ATT&CK 数据遵循 CC BY 4.0；语料逐条保留 attack.mitre.org 官方链接作为署名。

## 启动运行工作台

~~~powershell
uv run threat-agent-demo --serve        # 入口名沿用历史，页面即工作台
# 或 python -m threat_agent.bootstrap.demo --serve
~~~

浏览器访问 `http://127.0.0.1:8000/workbench`：事件接入（参考数据集/手工告警）→
运行视图（实时轨迹与终态自动刷新）→ 内联审批 → 报告审阅（证据引用可回溯到原始记录）。
知识面板展示每次咨询的入口、状态与命中条目（T-ID + 标题）。

## 参考数据对照（不调用模型）

~~~powershell
uv run threat-agent-demo --database outputs/demo-reference.sqlite --output outputs/demo-comparison.json
~~~

## 评测内核

`src/threat_agent/agent_eval/` 是可独立抽包的评测调度内核（与业务解耦，架构测试锁定）：

~~~python
from threat_agent.agent_eval import Runner, RunnerConfig, ScoreRunner, summarize

results = Runner(task, output_dir=Path("outputs/eval"), config=RunnerConfig(workers=4, epochs=3)).run_suite(cases)
report = summarize([r.record for r in results], cases_by_id, scores)
~~~

幂等续跑（仅跳过成功 run）、`fresh` 重采样、RPM/TPM 双维限流、单案失败隔离；
打分纯离线可 regrade。业务侧 CaseFactory / Scorer 集尚未接入（Feature 16 步骤 03/04）。

## 代码结构

~~~text
src/threat_agent/
├── bootstrap/          配置、依赖组装、工作台装配与 CLI
├── contracts/          跨模块稳定契约
├── case_management/    案件生命周期、运行服务、审批与 Checkpoint
├── data_foundation/    调查数据 Port 与本地 Adapter
├── judgment/           调查工具、报告接地与研判领域模型
├── agent_middleware/   可独立抽包的边界、预算与上下文治理中间件
├── agent_eval/         可独立抽包的评测调度内核（Feature 16）
├── response_advisory/  独立的处置建议图
├── knowledge/          供应方无关 RAG 端口：ATT&CK 文件语料 / 参考语料 / Null / 路由组合器
├── observability/      Langfuse 旁路 sink
├── presentation/       API、只读投影与运行工作台页面
└── shared/             无业务语义的基础类型
~~~

## 当前边界

- 单机单租户：无认证、RBAC 与真实租户解析，不要暴露给不受控调用方；
- 数据面为版本化合成参考数据集（L0–L3 数据等级）；生产 EDR/SIEM/数据湖尚未接入；
- `telemetry_field_manual` 等知识源仍为参考占位，真实告警字典未接入；
- 评测框架的业务适配器（出题、打分器、基线报告）未完成，内核行为有测试覆盖；
- 告警来源运行的 Checkpoint 回溯暂不可用（正式调查路径不受影响）。

## 文档

- [软件架构与 Feature 索引](.sdd/README.md)
- [整体软件架构](.sdd/softwareArchitecture.md)
- [Feature 17 运行工作台](.sdd/features/17-runtime-workbench/README.md)
- [Feature 18 ATT&CK 真实语料](.sdd/features/18-attack-knowledge-corpus/README.md)
- [Feature 16 评测框架](.sdd/features/16-agent-eval-framework/README.md)
- [Feature 15 agent_middleware](.sdd/features/15-agent-middleware-foundation/README.md)
- [运行时 Linux 调查 Skill](investigation_skills/linux-unknown-file/SKILL.md)
