# Unknown-File Threat Agent

面向 Linux 未知文件告警的证据化安全研判原型。当前实现以案件 JSON 和 JSONL 事件为输入，通过可替换 Planner、只读证据工具、确定性 Analyzer、Scope/Policy 和 Verdict Validator 输出可追溯的案件结论。

当前代码覆盖文件来源、后门/C2、数据窃取、勒索和受控跨主机调查。生产数据底座、RAG、处置建议循环、案件持久化和执行治理属于目标架构，尚未在当前原型中实现。

## 文档

- [软件架构与 Feature 设计](.sdd/README.md)
- [整体软件架构](.sdd/softwareArchitecture.md)
- [当前研判引擎设计](.sdd/features/judgment-engine/README.md)
- [历史文档归档](.sdd/archive/README.md)
- [运行时 Linux 调查 Skill](investigation_skills/linux-unknown-file/SKILL.md)

`.sdd` 是现行软件设计的唯一入口。归档文档用于追溯，不代表当前实现。

## 代码结构

```text
threat_agent/          研判引擎、模型、工具、策略和报告
cases/                 18 个确定性对照 Case
tests/                 自动化测试
investigation_skills/  DeepAgents Planner 运行时调查知识
.sdd/                  现行设计和历史归档
```

## 安装

项目要求 Python 3.11 或更高版本。使用 `uv` 创建项目环境并安装测试依赖：

```powershell
uv sync --extra dev
```

## 离线确定性运行

```powershell
.\.venv\Scripts\python.exe -m threat_agent.cli `
  --case cases\c2_malicious `
  --mode deterministic `
  --output outputs\c2_malicious
```

其他可用 Case 位于 `cases/`。

## DeepAgents 运行

在项目根目录 `.env` 中配置：

```text
THREAT_AGENT_API_KEY=<key>
THREAT_AGENT_API_BASE=<OpenAI-compatible endpoint>
MODEL_NAME=<model>
```

然后运行：

```powershell
.\.venv\Scripts\python.exe -m threat_agent.cli `
  --case cases\c2_malicious `
  --mode deepagents `
  --output outputs\c2_malicious_agent
```

也可以使用 `run_case.ps1` 或 `run_case.sh`。

## 测试

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

当前回归基线为 59 项测试和 18 个 Case；该数字是当前实现快照，后续能力变化时应同步更新。

如果尚未运行 `uv sync`、项目本地 `.venv` 不存在，可使用当前 Python 环境执行：

```powershell
python -m pytest -q
```
