# RAG 知识能力落地计划（已执行）

四步计划，每步有独立可运行的验收，全部在参考适配器（RK-09）上验证，不依赖真实 RAG 供应方。执行状态：**四步全部完成**，验收记录见 `rk-acceptance.md`。

## 第 1 步：知识能力底座 —— 完成

契约重写（业务三字段输入、标准化知识条目输出、7 态状态）、能力层场景服务（按源合并与失败隔离、类别级限制、状态聚合）、供应方形状内部 Port、参考适配器与 Null 供应方、授权执行上下文框架化（消灭调用方手工填授权）、`KnowledgeSettings` 配置。

验证：`tests/test_knowledge_capability.py`（24 项）+ 架构测试新增两条规则（业务模块只消费能力层；授权只在框架入口绑定）。覆盖 RK-01、05、07、08、09。

## 第 2 步：研判侧接入 —— 完成

基线检索固定节点（finish 路由必经，查询只用已验证行为构造）、三个按用途拆分的工具、结案知识咨询记录（只记录不阻断）、基线指引进报告组合上下文、事实隔离（接地校验拒绝知识引用）。

验证：`tests/test_knowledge_investigation.py`（10 项）。覆盖 RK-02、06。

## 第 3 步：处置侧接入 —— 完成

处置子图直调 Port 改为能力层场景服务（Port 下沉为适配层内部依赖，旧契约与旧 Port 删除）、并列呈现合并（全部合格结果、按相关性排序、冲突并列标注、推荐至多附理由）、处置校验器零改动回归、`ResponseAction.knowledge_refs` 可追溯引用。

验证：`tests/test_knowledge_response.py`（6 项）+ 既有处置策略回归。覆盖 RK-03。

## 第 4 步：贯通验收 —— 完成

审计留痕接入既有 OperationalEvent/AuditEvent 通道（action=`knowledge_consulted`，query_id 关联适配层明细）；RK-04 供应方换档演练（仅配置切换，业务面零改动）；RK-01～09 全量验收套件与验收记录。

验证：`tests/test_rk_acceptance.py`（17 项）；记录 `rk-acceptance-run.txt`、`rk-acceptance.md`。

## 边界

不在本计划内：真实供应方对接、管理面界面与驱动逻辑、case_memory、知识质量评测——均按设计另立实施需求。每步合入后全仓测试保持绿（终态 201 项通过）。
