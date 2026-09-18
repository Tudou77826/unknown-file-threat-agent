# 实施计划

四个步骤，每步带验证门槛；全程契约与能力层零变更。

## 步骤 1：语料供应方与路由组合器（纯代码，无数据依赖）

- `knowledge/adapters/attack_corpus.py`：`AttackCorpusRecord`（语料行模型）、
  `records_from_stix_bundle()` 纯函数、词法打分器、`AttackCorpusSupplier`（实现 `SupplierRetrievalPort`）。
- `knowledge/adapters/routing.py`：`RoutingSupplier`（按源路由 + catalog 合并）。
- 导出：`knowledge/adapters/__init__.py` 与 `knowledge/__init__.py` 增补（供应方细节不出包，包内导出）。
- 单测：解析夹具 / 检索 / 状态语义 / 路由（见 design §7）。

**门槛**：`pytest tests/test_attack_corpus.py tests/test_routing_supplier.py tests/test_knowledge_capability.py` 全绿。

## 步骤 2：离线构建脚本与中文化

- `scripts/build_attack_corpus.py`：下载 STIX（缓存 `downloads/`）→ 解析 → LLM 批跑中文化
  （复用 `build_chat_model(settings.judgment_model)`，缓存 `corpora/attack_llm_cache.json` 按 TID 幂等，
  4~8 并发，失败跳过）→ 写 `corpora/attack_technique.jsonl`（TID 排序）。
- 支持 `--limit` / `--no-llm` / `--source` / `--version` 参数；不重跑已缓存条目。

**门槛**：本机全量构建成功；JSONL 行数 ≈ 690±（过滤 revoked/deprecated 后）；抽检 5 条中文字段完整；
重跑一次全程零 LLM 调用（缓存命中）。

## 步骤 3：装配与展示

- `KnowledgeSettings`：`adapter` 加 `"attack"`、新增 `attack_corpus_path`；`.env.example` 更新。
- `bootstrap/demo.py build_knowledge_service`：`"attack"` 分支组装 RoutingSupplier。
- 知识库页：attack 适配器徽标与说明（pages.py 的 `render_knowledge` 增加分支）。

**门槛**：`KNOWLEDGE_ADAPTER=attack` 启动服务，`/workbench/knowledge` 显示 ATT&CK 目录（≈690 条）与
命中统计；`KNOWLEDGE_ADAPTER=reference` 行为与改动前完全一致（回归）。

## 步骤 4：门禁与实测

- `tests/test_architecture_dependencies.py` 新增：knowledge 叶子层规则（design §7）。
- 新增 `tests/test_attack_corpus_supplier.py` 真实语料冒烟（读仓库内 JSONL：条数下限、
  必备字段、真实行为句 top-3 命中断言——语料文件进 git，测试离线可跑）。
- 全量回归 `pytest`（既有 234+ 用例保持绿）。
- 实测：发起一次真实研判运行，确认基线知识节点 status=available 且命中 ATT&CK 条目；
  `lookup_attack_technique` 工具查询"计划任务持久化"返回 T1053 族。

**门槛**：全量测试绿 + 实测两项命中 + 参考适配器回归无差异。
