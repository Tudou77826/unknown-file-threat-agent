# Unknown-File Threat Agent

面向 Linux 未知文件告警的证据化安全调查 Demo。系统将规范化安全活动、实体关系和
受控原始记录提供给 AI 调查工具；正式研判循环采用 create_agent + middleware，
案件图负责生命周期、报告后的处置建议和审批中断。

## 当前边界

- 内置两个版本化参考数据集和 L0～L3 数据 Profile，用于展示数据能力对调查问题的影响；
- SQLite 仅是本地参考 Adapter；生产 EDR、SIEM、数据湖和知识检索尚未接入；
- API 与页面是本地 Demo，不具备认证、RBAC、真实租户解析或敏感事件展示控制；
- 运行记录可在重启后查询，但正在执行的任务不能从中断位置续跑。

这些限制的设计依据见
[Feature 08](.sdd/features/08-investigation-platform-foundation/README.md)。

## 文档

- [软件架构与 Feature 索引](.sdd/README.md)
- [整体软件架构](.sdd/softwareArchitecture.md)
- [运行时收敛与调查数据 Port 设计](.sdd/features/15-agent-middleware-foundation/runtime-convergence-design.md)
- [当前研判引擎设计](.sdd/features/02-judgment-engine/README.md)
- [运行时 Linux 调查 Skill](investigation_skills/linux-unknown-file/SKILL.md)

## 安装与验证

项目要求 Python 3.10 或更高版本，并使用 uv 管理锁定依赖。

~~~powershell
uv sync --extra dev --locked
uv run pytest -q
uv run threat-agent-demo --help
~~~

## 参考数据对照

以下命令只构建参考数据与数据就绪度对照，不调用模型：

~~~powershell
uv run threat-agent-demo --database outputs/demo-reference.sqlite --output outputs/demo-comparison.json
~~~

输出包含两个参考数据集在各个 Data Profile 下可回答的调查问题。它不代表生产
检出率、模型效果或真实环境数据质量。

## 启动本地 Demo

~~~powershell
uv run threat-agent-demo --serve
~~~

浏览器访问 /demo/c2-malicious-reference 或 /demo/c2-benign-reference。页面始终使用
框架中间件研判路径；不提供图路径与 middleware 路径的 A/B 选择。

要从页面启动在线调查，请在项目根目录的 .env 中配置兼容 OpenAI 的模型服务：

~~~text
THREAT_AGENT_API_KEY=<key>
THREAT_AGENT_API_BASE=<OpenAI-compatible endpoint>
MODEL_NAME=<model>
JUDGMENT_MODEL_NAME=<optional judgment model override>
RESPONSE_MODEL_NAME=<optional response model override>
MODEL_DISABLE_PROXY=<optional, true to bypass proxy env vars>
~~~

模型消息、工具参数和原始结果只应用于本地演示排障；不要将该服务暴露给不受控调用方。

## 代码结构

~~~text
src/threat_agent/
├── bootstrap/          配置、依赖组装和 CLI
├── contracts/          跨模块稳定契约
├── case_management/    案件生命周期、审批与 Checkpoint
├── data_foundation/    调查数据 Port 与本地 Adapter
├── judgment/           调查工具、报告接地与研判领域模型
├── agent_middleware/   可复用的边界、预算和上下文治理组件
├── response_advisory/  独立的处置建议图
├── knowledge/          RAG Port 与 Null Adapter
├── presentation/       API、只读投影和 Demo 页面
└── shared/             无业务语义的基础类型
~~~
