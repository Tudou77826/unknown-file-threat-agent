# Feature 19 — Verification

## 步骤 01：Case 与 Replay 契约（已验收 2026-09-29）

交付物：

- `src/threat_agent/capability_validation/`：独立契约包（架构门禁：不 import 其他 threat_agent 子包，同 agent_eval / agent_middleware 纪律）。
  - `case_model.py`：TestCase Schema——判定对象锚点（`judgment_target`，hash 与 replay `input.json` 强校验一致）、双层 Ground Truth（`behavior` 技术是否达成 + `file` 文件级判定，含 `abused` 档）、`expected_rule`（含受理回执要求）、`expected_ai`、遥测清单（事件文件 + 环境基线来源）、来源溯源、参数化规格。
  - `replay.py`：Replay 目录约定（`case.json` + `replay/{input.json,events/*.jsonl,coverage.json,artifacts/}`）、Canonical 事件契约（必需字段与 data_foundation 摄取路径对齐，测试外侧保证）、原始遥测信封与投影协议（探针十类 + 三类环境基线，对应 telemetry-scope.md；真实转换器属步骤 02）。
  - `derivation.py`：参数化派生——`{{param}}` 占位替换，Ground Truth 按构造共享（不可参数化），派生后重验字段完整与锚点一致。
  - `suite.py`：套件清单 + 内容摘要版本钉住（`case@suite_version`，沿 agent_eval 惯例）、git 存储 + 单工件 10 MiB 上限。
- `validation_cases/`：首批套件 `seccap-poc@2026.09.1`——`c2-malicious-elf`（含 `alt-endpoint` 变体，C2 端点参数化）与 `c2-benign-baseline`（良性基线），由 `cases/c2_malicious` / `cases/c2_benign` 转换。

验收门槛核验（`tests/test_capability_validation_step01.py`，8 例，全过）：

- 「一个手写 Case + Replay 可被完整加载」：套件加载含清单校验、遥测清单一致性、环境基线存在性、锚点 hash 一致、内容摘要验证；派生变体经真实摄取管线（`BatchIngestionService` + `ReferenceEventParser`）入库成功、零隔离记录。
- 「参数化派生变体共享 Ground Truth 且字段完整」：变体 GT 与基例逐字相等；占位符替换后无残留；未知参数与锚点不一致均拒绝。
- 双层 GT 必填由 Schema 强制（缺层拒绝）。
- 架构门禁：`capability_validation` 不 import threat_agent 业务模块（`test_architecture_dependencies.py` 新增规则）。

存储决策（步骤 01 裁决）：测试资产直接进 git；二进制入 `replay/artifacts/`，单工件上限 10 MiB（技术选择已优先小体积 ELF）；对象存储为后置迁移，目录约定保证可移植。
