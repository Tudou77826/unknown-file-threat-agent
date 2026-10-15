# 态势感知数据适配模块

为 AI 研判系统定义统一的数据查询接口，隐藏已有态势感知数据库和 IR 接口的差异。模块内部可以查数据库、调用 IR 或组合使用，上层按相同接口获取数据。

模块与态势感知系统在内网一起维护；具体进程部署和通信方式由接入环境决定。

## 文档

- [design.md](design.md)：模块职责、接口和输入输出约定。
- [real-source-integration.md](real-source-integration.md)：真实源端接入的缺口清单、代码落位、工具层方案、开放点与验收门槛。

## 状态

接口、实现与单元测试已完成：`SituationalAwarenessDataAdapter` 复用 `InvestigationDataPort`，补充告警、文件信誉、资产信息、源端研判结果查询与认证活动查询，并接入注入式数据面（运行、审批、调试、断点恢复共用同一适配器）。

真实源端接入待做，缺口与开放点见 [real-source-integration.md](real-source-integration.md)：源端 handler 与目录落位、serve 桥接、AI 工具层暴露（4 个新工具）、验收验证。
