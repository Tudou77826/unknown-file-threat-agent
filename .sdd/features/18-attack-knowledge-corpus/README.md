# ATT&CK 真实语料接入（词法 RAG 占位）

把 `attack_technique` 知识源从 3 条手写条目升级为 MITRE ATT&CK 官方开源数据集（STIX 2.1，Enterprise 域约 690+ 条技术/子技术），检索走零依赖词法匹配 + T-ID 精确通道，中文化由构建期一次性 LLM 批跑固化进语料文件。其余四类知识源维持现状（真实数据到位前不动，投毒/租户夹具原样保留）。

定位：**验证性占位**——用于打通"真实规模语料"的检索链路并支撑调测演练，不承担研判质量；将来内网 RAG 到位后整体替换，业务面零改动（Feature 04 的供应方端口保证这一点）。

核心不变式：**契约与能力层零变更**——本需求只动适配层、管理面配置与离线构建工具；业务模块对语料来源无感知。

## 文档

- [design.md](design.md)：现状缺口、方案选型（词法 vs 向量）、模块划分、数据管线、检索算法、测试防护与架构规则。
- [implementation-plan.md](implementation-plan.md)：四个实施步骤与验证门槛。

## 状态

已实施完成（2026-09-18）：语料 `corpora/attack_technique.jsonl`（ATT&CK v19.2 Enterprise，697 条，中文覆盖 697/697）；
供应方 `knowledge/adapters/attack_corpus.py` + 路由组合器 `knowledge/adapters/routing.py`；
构建脚本 `scripts/build_attack_corpus.py`（LLM 缓存幂等，重跑零调用）。
实测：`KNOWLEDGE_ADAPTER=attack` 下基线咨询与 `lookup_attack_technique` 工具均返回真实 T-ID 条目
（模型在 claim 中映射 T1543.002 且证据引用全部指向活动数据）；处置侧 SOP 引用不受影响（路由正确）。
测试：新增 3 个门禁文件 27 例 + 架构规则 2 条，全量 257 例绿。
