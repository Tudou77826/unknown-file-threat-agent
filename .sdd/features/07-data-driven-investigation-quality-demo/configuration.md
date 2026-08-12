# Runtime Configuration Design

## 1. 配置边界

根目录 `.env` 管理部署环境和一次运行的默认参数。实际密钥只允许存在于未跟踪的 `.env` 或进程环境变量中；`.env.example` 只提供安全示例。

以下内容不是环境配置：案件输入、Evidence、期望 Verdict、人工审批决定、证据门槛、工具评分权重和领域判定规则。这些内容分别属于运行输入、参考数据或版本化代码。

## 2. 配置分组

| 分组 | 配置项 | 作用 |
|---|---|---|
| 应用 | `THREAT_AGENT_ENV` | `development`、`demo` 或 `production` |
| 应用 | `THREAT_AGENT_MODE` | 默认使用确定性或 LLM Planner |
| 应用 | `THREAT_AGENT_DEFAULT_TENANT`、`THREAT_AGENT_DEFAULT_RUN_ID` | 本地默认运行标识 |
| 路径 | `THREAT_AGENT_DEFAULT_CASE_DIR`、`THREAT_AGENT_OUTPUT_DIR` | 默认输入与输出位置 |
| Checkpoint | `THREAT_AGENT_CHECKPOINT_BACKEND`、`THREAT_AGENT_CHECKPOINT_PATH` | 内存或 SQLite Checkpoint |
| 图运行 | `THREAT_AGENT_GRAPH_RECURSION_LIMIT` | 父图和子图运行上限 |
| 研判预算 | `JUDGMENT_MAX_ITERATIONS`、`JUDGMENT_MAX_TOOL_CALLS`、`JUDGMENT_MAX_SCOPE_EXPANSIONS`、`JUDGMENT_MAX_REPAIR_ACTIONS`、`JUDGMENT_MAX_VERDICT_REPAIRS` | 研判循环资源边界 |
| 处置预算 | `RESPONSE_MAX_ITERATIONS` | 处置建议循环资源边界 |
| 查询 | `EVIDENCE_QUERY_DEFAULT_LIMIT`、`EVIDENCE_QUERY_MAX_LIMIT` | 数据查询结果边界 |
| 模型公共 | `THREAT_AGENT_API_KEY`、`THREAT_AGENT_API_BASE` | OpenAI 兼容服务凭据与地址 |
| 研判模型 | `JUDGMENT_MODEL_NAME`、`JUDGMENT_MODEL_MAX_TOKENS`、`JUDGMENT_MODEL_TIMEOUT_SECONDS`、`JUDGMENT_MODEL_MAX_RETRIES`、`JUDGMENT_MODEL_TEMPERATURE` | 研判模型参数 |
| 处置模型 | `RESPONSE_MODEL_NAME`、`RESPONSE_MODEL_MAX_TOKENS`、`RESPONSE_MODEL_TIMEOUT_SECONDS`、`RESPONSE_MODEL_MAX_RETRIES`、`RESPONSE_MODEL_TEMPERATURE` | 处置模型参数 |
| Demo 数据 | `DEMO_DATA_STORE_PATH`、`DEMO_DATASET_VERSION`、`DEMO_DATA_PROFILE`、`DEMO_RANDOM_SEED` | 参考存储、要求的数据版本与种子，以及页面默认聚焦的 Profile；实际 Profile 和种子仍由版本化参考资产定义并校验 |
| 展示 | `THREAT_AGENT_API_HOST`、`THREAT_AGENT_API_PORT` | 只读展示服务监听地址 |
| 日志 | `THREAT_AGENT_LOG_LEVEL` | 运行日志级别 |

保留 `MODEL_NAME` 和 `SILICONFLOW_API_KEY` 的兼容期必须明确且有删除时间；新代码只使用统一命名后的配置对象。

## 3. 加载与校验

- 只有 `bootstrap` 可以读取 `.env` 和进程环境变量。
- 配置加载后形成不可变 `AppSettings`，再向各模块注入子配置。
- 相对路径以项目根目录解析，日志输出时不得打印密钥。
- LLM 模式必须配置 API Key、Base URL 和两个模型名；确定性模式不得要求模型凭据。
- SQLite Backend 必须提供 Checkpoint 路径；Memory Backend 忽略该路径并产生明确提示。
- Demo Profile 必须属于指定数据集版本，随机种子必须为整数。
- 端口、预算、超时和查询上限必须为正数，并具有合理最大值。

## 4. `.env.example` 原则

`.env.example` 应提供可以直接运行离线 Demo 的非敏感值，模型凭据留空。示例文件按上述分组排序并附最少注释，不复制领域规则或测试数据。
