# Case Governance Design

```mermaid
stateDiagram-v2
    [*] --> Open
    Open --> Investigating
    Investigating --> AwaitingInput
    AwaitingInput --> Investigating
    Investigating --> Judged
    Judged --> Advising
    Advising --> AwaitingApproval
    AwaitingApproval --> Executing
    AwaitingApproval --> Closed
    Executing --> Monitoring
    Monitoring --> Closed
    Investigating --> Closed
```

## 组件

- Case Store：案件聚合、版本和并发控制。
- Run Scheduler：研判和处置任务的队列、租约、重试和预算。
- Authorization Service：身份、角色、数据 Scope 和动作权限。
- Approval Service：审批请求、超时、拒绝和职责分离。
- Audit Store：追加式运行记录和证据引用。
- Execution Gateway：向 SOAR、EDR、IAM 等系统提交经批准动作。

## 一致性

案件状态更新使用乐观并发或事件序号。工具调用与状态写入使用幂等键；外部执行采用提交、查询状态和补偿流程，不假设分布式事务。
