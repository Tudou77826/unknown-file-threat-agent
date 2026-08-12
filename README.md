# Unknown-File Threat Agent

面向 Linux 未知文件告警的证据化安全分析平台。当前实现通过 LangGraph 父图编排研判与处置建议两个循环，并提供 JSONL/Fixture 与 SQLite 参考数据适配器、可追溯案件视图和数据质量对照 Demo。

当前代码覆盖文件来源、后门/C2、数据窃取、勒索、受控跨主机调查、结构化处置建议、Checkpoint 和只读展示。RAG 仅保留接口与 Null Adapter；生产数据源、知识检索和处置执行尚未接入。

## 文档

- [软件架构与 Feature 设计](.sdd/README.md)
- [整体软件架构](.sdd/softwareArchitecture.md)
- [当前研判引擎设计](.sdd/features/02-judgment-engine/README.md)
- [历史文档归档](.sdd/archive/README.md)
- [运行时 Linux 调查 Skill](investigation_skills/linux-unknown-file/SKILL.md)

`.sdd` 是现行软件设计的唯一入口。归档文档用于追溯，不代表当前实现。

## 代码结构

```text
src/threat_agent/      按业务能力组织的应用代码
├── bootstrap/         配置、依赖组装和 CLI
├── contracts/         跨模块稳定契约
├── case_management/   案件父图、审批、Checkpoint 和结果提交
├── data_foundation/   证据查询端口与本地数据适配器
├── judgment/          研判领域、LangGraph 子图和调查工具
├── response_advisory/ 处置建议领域、LangGraph 子图和上下文端口
├── knowledge/         RAG 端口与 Null Adapter
├── presentation/      只读 Store、API 和序列化投影
└── shared/            无业务含义的基础类型
cases/                 18 个确定性对照 Case
demo_data/             版本化参考数据清单与 L0～L3 Data Profile
tests/                 自动化测试
investigation_skills/  结构化 LLM Planner 运行时调查知识
.sdd/                  现行设计和历史归档
```

## 安装

项目要求 Python 3.10 或更高版本。使用 `uv` 创建项目环境并安装测试依赖：

```powershell
uv sync --extra dev
```

## 离线确定性运行

```powershell
.\.venv\Scripts\python.exe -m threat_agent.bootstrap.cli `
  --case cases\c2_malicious `
  --mode deterministic `
  --output outputs\c2_malicious
```

其他可用 Case 位于 `cases/`。

## 数据质量对照 Demo

一次运行会初始化本地 SQLite 参考数据，并执行恶意与合法两个数据集的 L0～L3 共 8 条路径：

```powershell
python -m threat_agent.bootstrap.demo `
  --database outputs\demo-reference.sqlite `
  --output outputs\demo-comparison.json
```

启动只读展示页：

```powershell
python -m threat_agent.bootstrap.demo --serve
```

浏览器访问 `/demo/c2-malicious-reference` 或 `/demo/c2-benign-reference`。四列结果是可重复的确定性基线；配置模型后，可点击任一数据层，用双 LLM 实时重跑并查看调查事件轨迹。页面展示的是结构化决策和工具事件，不暴露或伪造模型内部思维。参考数据仅用于展示数据能力与研判质量的关系，不代表生产准确率。

## 双 LLM 运行

在项目根目录 `.env` 中配置：

```text
THREAT_AGENT_API_KEY=<key>
THREAT_AGENT_API_BASE=<OpenAI-compatible endpoint>
MODEL_NAME=<model>
JUDGMENT_MODEL_NAME=<optional judgment model override>
RESPONSE_MODEL_NAME=<optional response model override>
```

然后运行：

```powershell
.\.venv\Scripts\python.exe -m threat_agent.bootstrap.cli `
  --case cases\c2_malicious `
  --mode llm `
  --output outputs\c2_malicious_agent
```

也可以使用 `run_case.ps1` 或 `run_case.sh`。

## 测试

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

当前回归基线为 119 项测试和 18 个 Case；其中包含模块依赖方向、配置、双循环、参考数据和 8 条 Profile 路径检查。

如果尚未运行 `uv sync`、项目本地 `.venv` 不存在，可使用当前 Python 环境执行：

```powershell
python -m pytest -q
```
