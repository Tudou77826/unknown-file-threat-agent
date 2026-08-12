# Data Foundation Design

## 组件

```mermaid
flowchart LR
    S["Sources"] --> C["Connectors"]
    C --> P["Parsers / Normalizers"]
    P --> M["Canonical Security Model"]
    M --> RT["Realtime / Analytics Store"]
    M --> HS["Historical Store"]
    RT --> Q["Query Gateway"]
    HS --> Q
    Q --> A["Authorized Evidence API"]
```

### Connectors

处理认证、增量读取、断点续传、限流和源端错误，不进行威胁判断。

### Parsers and Normalizers

将源字段映射到进程、文件、网络、DNS、认证、持久化和资产等规范模型。解析失败记录必须进入隔离区并保留原因。

### Storage

实时层服务低延迟研判，历史层服务长时间回溯和基线计算。存储技术可替换，查询契约不应绑定具体引擎。

### Query Gateway

负责身份传递、Scope 下推、查询预算、分页、超时、Coverage 和审计。研判引擎不得直接连接底层存储。

## 与当前代码的兼容

当前 `EvidenceQueryPort` 接收显式 `EvidenceQuery`，包含租户、案件、Scope、查询参数和结果上限。JSONL/Fixture Repository 位于数据底座 Adapter 内部，只接收最小 `ScopeContext`，不依赖 `InvestigationState`。生产化仍需补充分页令牌、数据级 RBAC、审计和真实存储连接器。
