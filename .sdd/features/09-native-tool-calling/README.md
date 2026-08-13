# Native Tool Calling

研判引擎的证据/分析工具路径目前用 `with_structured_output(json_mode)` 让模型返回一个 `tool_name` 字符串，再由确定性代码补齐参数，属于伪 agentic。本 Feature 将其升级为原生 function calling（`bind_tools` + `tool_calls` + `ToolMessage` 回灌），与已实现的数据工具路径 `StructuredDataToolPlanner` 对齐，同时保留确定性护栏（catalog 资格约束、`validate_action` 策略、确定性 Analyzer 与 Verdict 门槛）。

## 文档

- [design.md](design.md)

## 当前状态

设计待审批；尚未实现。
