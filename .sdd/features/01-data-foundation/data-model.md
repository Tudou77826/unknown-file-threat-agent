# Canonical Security Data Model

## 公共字段

所有事件至少包含：

```text
schema_version
tenant_id
event_id
event_type
event_time
ingest_time
source_system
host_id
subject_refs
outcome
raw_reference
```

事件时间与采集时间必须分开。PID 必须与主机、进程开始时间组合使用；跨重启场景应补充 boot/session 标识。

## 事件族

- ProcessEvent：创建、执行、退出、父子关系和命令行。
- FileEvent：创建、读取、写入、改名、删除、Hash 和内容变化指标。
- NetworkSessionEvent：进程归属、方向、端点、协议、字节和结果。
- DnsEvent：查询名、响应、进程归属和载荷特征。
- AuthenticationEvent：账号、会话、来源、认证方式和结果。
- PersistenceEvent：配置写入、启用、启动和执行结果。
- AssetContext：资产角色、业务关键度、所有者、环境和批准关系。

## Coverage

Coverage 至少描述：

- 请求范围；
- 数据可用范围；
- 返回结果范围；
- 完整、部分、未知或不可用；
- 截断、延迟和来源限制。

空结果只有在 Coverage 完整且查询覆盖全部必要条件时，才能支持有限的否定结论。
