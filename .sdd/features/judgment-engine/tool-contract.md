# Judgment Tool Contract

## 工具分类

- Evidence Tool：查询数据底座，返回事件和 Coverage。
- Analysis Tool：读取明确授权的 Evidence，返回 Fact、Finding 和 Relation。
- Knowledge Tool：查询 RAG，返回带来源的知识，不产生案件事实。
- Scope Tool：提交有证据支撑的调查扩展申请。

## 公共声明

每个工具必须声明：名称、版本、用途、输入 Schema、输出 Schema、所需权限、成本级别、超时、幂等策略和限制。

## 调用要求

- 每次调用携带 `tenant_id`、`case_id`、`call_id`、调用身份和 Scope。
- Evidence Tool 返回空结果时必须返回 Coverage。
- Analysis Tool 只能读取请求中列出的 Evidence ID。
- 工具失败不得被转换成“没有发现攻击”。
- 具有副作用的工具不属于研判工具目录。

## 当前实现映射

当前 `ToolDefinition`、`ToolRegistry`、`EvidenceBundle` 和 `FactFindingBundle` 是本契约的原型。后续应从集中式映射迁移到版本化 Tool Manifest。
