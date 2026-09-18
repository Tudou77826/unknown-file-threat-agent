# ATT&CK 真实语料接入 — Design

## 1. 背景与缺口

知识链路五层（契约 → 能力层 → 供应方端口 → 适配器 → 消费点）在 Feature 04/17 已建齐且有测试；
缺口全部在数据面与检索面：

| 缺口 | 现状 | 差距 |
|---|---|---|
| ATT&CK 覆盖 | 3 条手写条目（T1053.003 / T1071.001 / T1547.005） | 官方 Enterprise 域 222 技术 + 475 子技术 ≈ 697 条 |
| 检索方式 | 关键词包含匹配（手写中文 keywords 兜底） | 中文行为句查英文语料基本无召回；语料规模化后彻底失效 |
| 语料管理 | 17 条硬编码在 `reference_retriever.py` 源码 | 换语料 = 改代码；无外部数据文件、无版本化、无重建口 |
| 告警解释 / 处置侧语料 | 手写占位 | 真实数据未到位（本需求不动，仅预留文件化扩展位） |

消费点现状（本需求不改动它们）：研判侧强制基线节点（经验 + ATT&CK）与三个按需工具
（`lookup_attack_technique` / `interpret_telemetry_field` / `consult_judgment_experience`）；
处置侧生成方案前的 `response_policy_reference` 咨询。

## 2. 目标与非目标

### 目标

1. `attack_technique` 源接入 MITRE ATT&CK 官方开源数据集（CC BY 4.0，STIX 2.1，
   `mitre-attack/attack-stix-data` 仓库，当前 v19.2），全量技术 + 子技术，过滤 revoked / deprecated。
2. 检索实现为纯 Python 词法匹配：CJK 字符二元组 + ASCII 词元 + T-ID 精确通道，确定性、零新增运行时依赖。
3. 中文可用性由**构建期一次性 LLM 批跑**解决：每条技术生成中文标题 / 摘要 / 关键词，固化进语料文件；
   运行时不调 LLM、不联网。
4. 语料外部化：JSONL 数据文件 + 版本戳 + 可重建脚本；语料与 LLM 缓存进 git，STIX 原始包（约 40MB）不进。
5. 架构整洁：契约与能力层零变更；新增代码全部位于 `knowledge/adapters/`（叶子层）+ `scripts/`（离线工具）
   + bootstrap 装配；新增架构门禁锁定依赖方向。

### 非目标

- 向量检索 / 本地 embedding（已评估并否决：验证定位下运行时零新依赖优先；将来升级只改适配器内部）；
- 其余四类知识源（经验 / 遥测手册 / SOP / 处置经验）的真实数据接入与语料迁移；
- 内网 RAG 对接（部署期需求，端口已就绪）；
- ATT&CK 的 Group / Software / Campaign / Mobile / ICS 域；
- 检索质量调优到"可依赖"水平——本语料是验证性占位。

## 3. 方案选型：为什么是词法 + 离线中文化

| | 词法（选定） | 本地向量（否决） |
|---|---|---|
| 运行时新增依赖 | 无 | fastembed + 100~400MB 模型文件 |
| 中英跨语言 | 靠构建期 LLM 中文化后**同语种匹配** | 原生支持 |
| 确定性 / 可测试 | 完全确定 | 依赖模型版本一致性 |
| 决策依据 | 验证定位：链路通、可演练、可离线交付即可 | 质量上限更高，但本需求不承担质量 |

词法直接查英文原文的致命伤（中文查询与英文语料零字面重合）由中文化步骤消除：
检索索引建立在"中文标题 + 中文摘要 + 中文关键词 + 英文标题 + T-ID"上，
T-ID 精确通道保证模型直接给技术编号时一击命中。

## 4. 模块划分与数据流

```
离线（一次性 / 数据更新时重跑）                    运行时（零网络、零 LLM）
─────────────────────────────                ─────────────────────────────
scripts/build_attack_corpus.py               knowledge/adapters/attack_corpus.py
  ① 下载 enterprise-attack.json (downloads/)   AttackCorpusSupplier
  ② STIX attack-pattern → 中间记录                ├─ 启动时读 corpora/attack_technique.jsonl
     （knowledge/adapters/attack_corpus.py       ├─ 词法打分：T-ID 精确 + bigram/词元重叠
        提供 records_from_stix_bundle 纯函数）     └─ catalog()：语料清单给运营面
  ③ LLM 批跑中文化（缓存 corpora/                knowledge/adapters/routing.py
     attack_llm_cache.json，按 TID 幂等）        RoutingSupplier（按源路由 + catalog 合并）
  ④ 写出 corpora/attack_technique.jsonl
                                             bootstrap/demo.py build_knowledge_service
                                               adapter == "attack" 时：
                                               RoutingSupplier(
                                                 {"attack_technique": AttackCorpusSupplier(...)},
                                                 default=ReferenceKnowledgeAdapter(profile))
```

要点：

- **组合优于改造**：`ReferenceKnowledgeAdapter` 是验收与演练的夹具台（故障注入、投毒样本、租户隔离、
  供应方互换），保持原样不动；ATT&CK 供应商只接手 `attack_technique` 一个类别，其余四类继续走参考适配器。
  这使两套语料互不污染，也保住既有 RK 验收测试。
- **RoutingSupplier 是通用组合器**：按 `SupplierSourceQuery.source_category` 把请求拆给路由表中的
  供应方，未列出的类别走默认供应方；catalog 按类别合并（路由侧覆盖默认侧同名类别）。
  它不认识"ATT&CK"，只认识端口。
- **构建逻辑可测**：STIX 解析是 `knowledge/adapters/attack_corpus.py` 里的纯函数
  （`records_from_stix_bundle(bundle, attack_version)`），脚本只是 IO 壳；测试用微型 STIX 夹具覆盖。
- **脚本可依赖 src，src 永不依赖脚本**：依赖方向由架构测试锁定。

## 5. 数据契约

### 5.1 语料记录（JSONL，每行一条）

```json
{
  "knowledge_id": "T1053.003",
  "version": "19.2",
  "chunk_id": "c1",
  "title_en": "Scheduled Task/Job: Cron",
  "title_zh": "计划任务：Cron",
  "summary_zh": "攻击者滥用 cron 实现定时执行与持久化……",
  "keywords": ["计划任务", "cron", "定时执行", "持久化", "t1053"],
  "content_en": "战术: Persistence, Privilege Escalation; 平台: Linux…\n描述: …\n检测: …",
  "tactics": ["persistence", "privilege-escalation"],
  "platforms": ["Linux"],
  "data_sources": ["Scheduled Task Store"],
  "source_uri": "https://attack.mitre.org/techniques/T1053/003/",
  "built_by": "attack-corpus/1"
}
```

映射到 `SupplierItem`（查询时）：`title = f"{title_zh}（{title_en}，{tid}）"`，
`summary = summary_zh`，`content = summary_zh + 结构化英文原文`（截断保护模型上下文），
`supplier_metadata = {tactics, platforms, data_sources}`，`relevance` 由打分归一。
中文化缺失时回退英文（构建脚本 LLM 失败不留死数据，下次重跑补齐缓存）。

### 5.2 LLM 缓存（corpora/attack_llm_cache.json）

按 TID 键控：`{"T1053.003": {"title_zh": …, "summary_zh": …, "keywords": […], "cached": {"model": …, "attack_version": …}}}`。
重跑幂等：已有缓存不重调；ATT&CK 升版后可整表失效重生成。

### 5.3 设置（管理面）

`KnowledgeSettings.adapter` 增加 `"attack"`；新增 `attack_corpus_path`（默认
`corpora/attack_technique.jsonl`，env `KNOWLEDGE_ATTACK_CORPUS`）。语料文件缺失时供应方
按源返回 `not_configured`（能力层会如实呈现状态，不伪装成"没有相关知识"）。

## 6. 检索算法（确定性）

1. **T-ID 精确通道**：查询文本中出现 `T\d{4}(\.\d{3})?` 且命中某条目的 `knowledge_id` → 该条目置顶，相关性 high。
2. **词法通道**：
   - 查询侧：剥掉能力层查询文本的固定标签前缀（"已验证行为:" 等）后切词；
     CJK 连续段出字符二元组，ASCII 段出小写词元。
   - 条目侧：`title_zh + summary_zh + keywords + title_en + tactics` 切出同一套词元集合。
   - 得分：ASCII 词命中权重 1.0、CJK 二元组 0.6（单个二元组命中视为噪音，需至少一个词命中
     或两个二元组命中）；`score = 加权重叠 / max(1, sqrt(|条目词元集|))`。
   - 归一与淘汰：`score ≥ 0.45 → high`，`≥ 0.25 → medium`，**低于 0.25 的条目不返回**——
     697 条规模下偶然二元组命中聚在 0.13~0.20，真实行为句命中从 0.33 起步，中档线即噪音线
     （阈值以真实语料校准并固化进测试）。
3. top_k 默认 3（沿用能力层 options），并列时按 TID 字典序稳定排序。

## 7. 测试防护

| 层 | 防护 |
|---|---|
| STIX 解析 | 微型 STIX 夹具：TID 提取（含子技术）、revoked/deprecated 过滤、tactics/platforms 抽取、source_uri 还原、版本戳 |
| 检索质量 | 真实行为句（"计划任务持久化 + 固定间隔回连"）断言 top-3 命中 T1053 / T1071 族；T-ID 精确通道；无关联查询返回 empty 而非噪音；中文化缺失时英文回退可用 |
| 状态语义 | 语料文件缺失 → not_configured（不伪装 empty）； RoutingSupplier 按源路由正确、漏报来源按 error 归一（能力层既有行为） |
| 兼容 | 既有 knowledge / RK 验收 / workbench 测试全量保持绿（参考适配器未动） |
| 架构 | 新增规则：`knowledge` 包不得 import `bootstrap/judgment/response_advisory/case_management/presentation/data_foundation/observability`（叶子层锁定）；`scripts/` 不被 src 引用 |
| 展示 | 知识库页在 attack 适配器下渲染目录条数与配置徽标（catalog 形状与参考适配器一致） |

## 8. 风险与边界

- **LLM 中文化质量**：flash 档模型偶发格式漂移 → 严格 JSON 解析 + 一次重试 + 失败跳过（缓存不落脏数据）；
  英文原文始终保留在 content 里兜底。
- **语料体积**：约 690 条 × 1~2KB ≈ 1~2MB JSONL，进 git 无压力；知识库页目录全量渲染约 700 行表格，可接受。
- **许可**：MITRE ATT&CK 为 CC BY 4.0，`source_uri` 逐条保留官方链接即署名；仅内部使用。
- **升级路径**：ATT&CK 季度发版 → 重跑脚本（缓存幂等）→ 换 JSONL；换内网 RAG → 新适配器替 RoutingSupplier 路由项。
