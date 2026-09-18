# Runtime Convergence and Investigation Data Port Design

## 1. 状态与目标

状态：已实施。

本次收敛将在线调查的正式研判循环固定为 LangChain 推荐的
create_agent + middleware 形态，并消除用户、API 与运行服务可选择
两套编排的接口。案件生命周期、审批中断和处置建议仍由 CaseGraph
承担；它们不是 LLM 工具循环的替代实现。

同时，调查工具网关不再直接依赖 SQLite Store 或 SQLite Query Adapter。
它只依赖聚合的 InvestigationDataPort，由 Data Foundation 负责把具体
EDR、SIEM、数据湖或本地 SQLite 的读取能力适配为同一组类型化读操作。

## 2. 范围

### 2.1 正式运行时

- MiddlewareJudgmentRunner 是 Demo 和调查服务唯一组装的研判子图；
- InvestigationCreateRequest 不再有 runtime 字段；
- 传入旧 runtime 字段的请求因严格契约校验返回 422；
- 调查读模型不再回显运行时选择值；
- Demo 页面只说明框架中间件路径，不提供 A/B 选择器或差异面板；
- Run 的 source_identity 固定标注 framework-middleware，用于审计追溯实现
  版本，而不是向调用方提供路由选择。

保留的 JudgmentGraph 源文件不属于支持的运行时接口，也不由 bootstrap、
CaseGraph 或 API 组装。它暂时只保留为迁移期内部参考和既有低层测试资产；
不得继续新增功能或重新暴露为第二条线上路径。物理删除应在其剩余低层测试完成
迁移后独立执行。

### 2.2 调查数据访问 Port

InvestigationDataPort 聚合单次调查需要的以下读取能力：

| 能力 | Port 操作 | 责任 |
|---|---|---|
| 按领域查询活动 | query_process/network/socket/file/service/package/asset/extension | 返回带接口定义与执行边界的活动结果 |
| 实体与关系 | resolve_entity、find_relations | 隐藏实体别名与关系存储实现 |
| 实体时间线 | list_entity_timeline | 在 Adapter 内执行时间、主机、分页和来源可见性限制 |
| 原始记录 | get_raw_record | 只在活动仍对当前数据 Profile 可见时返回托管载荷 |
| 指标输入 | get_activities | 向确定性指标计算提供已授权活动，而非数据库对象 |

SQLiteInvestigationDataAdapter 是首期实现。它内部组合
SQLiteActivityQueryAdapter 和 SQLiteActivityStore；两者不再穿透到
judgment。可见数据源限制必须同时作用于领域查询、时间线、原始记录和关系
读取，避免 Profile 仅限制一种读取路径。

## 3. 目标结构

~~~mermaid
flowchart LR
    UI[Demo UI] --> API[Investigation API]
    API --> RUN[DemoRunService]
    RUN --> CASE[CaseGraph: lifecycle and approval]
    CASE --> AGENT[MiddlewareJudgmentRunner]
    AGENT --> GW[InvestigationToolGateway]
    GW --> PORT[InvestigationDataPort]
    PORT --> SQLITE[SQLite adapter today]
    PORT -. replaceable .-> PROVIDER[EDR / SIEM / data lake adapter]
    AGENT --> REPORT[Report publication pipeline]
~~~

依赖方向为：

1. judgment → data_foundation.ports；
2. data_foundation.adapters → SQLite 或未来 Provider SDK；
3. bootstrap 负责将具体 Adapter 注入网关；
4. case_management 只消费 JudgmentStagePort.compiled，不依赖某个具体研判实现。

## 4. 验收标准

| 编号 | 验收条件 |
|---|---|
| RC-01 | investigation_tools.py 不出现 SQLiteActivityStore 或 SQLiteActivityQueryAdapter，架构测试锁定该约束。 |
| RC-02 | 同一数据 Profile 下，隐藏来源不能经实体时间线、原始记录或指标活动读取绕过。 |
| RC-03 | run_demo_profile、DemoRunService.start 与 API 路由均无 runtime 选择参数。 |
| RC-04 | 页面不包含运行时选择控件；旧 runtime 请求被严格拒绝。 |
| RC-05 | MiddlewareJudgmentRunner 继续覆盖正常完成、预算降级和边界拒绝三类路径。 |
| RC-06 | CI 从 lockfile 创建环境，执行完整测试和真实 CLI help 命令。 |

## 5. 非目标与关联限制

本次不改变 Feature 08 已记录的生产化缺口：活动中断后的任务恢复、可信身份、
RBAC、真实租户解析和受控事件展示仍未交付。运行时收敛不能被解释为这些能力已经
具备。
