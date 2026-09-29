# Feature 19 — Verification

## 步骤 01：Case 与 Replay 契约（已验收 2026-09-29）

交付物：

- `src/threat_agent/capability_validation/`：独立契约包（架构门禁：不 import 其他 threat_agent 子包，同 agent_eval / agent_middleware 纪律）。
  - `case_model.py`：TestCase Schema——判定对象锚点（`judgment_target`，hash 与 replay `input.json` 强校验一致）、双层 Ground Truth（`behavior` 技术是否达成 + `file` 文件级判定，含 `abused` 档）、`expected_rule`（含受理回执要求）、`expected_ai`、遥测清单（事件文件 + 环境基线来源）、来源溯源、参数化规格。
  - `replay.py`：Replay 目录约定（`case.json` + `replay/{input.json,events/*.jsonl,coverage.json,artifacts/}`）、Canonical 事件契约（必需字段与 data_foundation 摄取路径对齐，测试外侧保证）、原始遥测信封（kind 约束在探针十类 + 三类环境基线内）与投影协议（真实转换器属步骤 02）。
  - `derivation.py`：参数化派生——`{{param}}` 占位替换，Ground Truth 按构造共享且必须字面（含占位符的 GT 在加载时拒绝），派生后全量扫描无残留占位符并重验锚点。
  - `suite.py`：套件清单（case_id/directory 唯一性校验）+ 内容摘要版本钉住（`case@suite_version`，沿 agent_eval 惯例）、git 存储 + 工件上限（manifest `storage.artifact_max_bytes` 优先于内置默认 10 MiB）。
- `validation_cases/`：首批套件 `seccap-poc@2026.09.1`——`c2-malicious-elf`（含 `alt-endpoint` 变体，C2 端点参数化）与 `c2-benign-baseline`（良性基线），由 `cases/c2_malicious` / `cases/c2_benign` 转换。

### 严格验收（2026-09-29，功能 / 架构 / 性能三关）

**功能关：对抗性探测 5 项发现，全部修复并转为回归测试**（`tests/test_capability_validation_step01.py`，13 例）：

| 发现 | 处置 |
|---|---|
| `RawTelemetryEnvelope.kind` 接受任意字符串，探针十类范围未强制 | 加校验器：kind 必须属于 `RAW_TELEMETRY_KINDS` |
| GT 内含**已声明**参数占位符时静默留存字面 `{{...}}`（未知名会报错属意外兜底） | 加载时强制 GT 字面性；物化后对整个派生 case 全量扫描残留占位符 |
| manifest 允许重复 case_id / directory | `SuiteManifest` 唯一性校验 |
| `judgment_target` 仅校验 hash，path/type 与 `input.json` 不一致不检出 | 锚点校验扩展到 path + type（加载与派生两侧） |
| manifest `storage.artifact_max_bytes` 声明未被代码读取 | `load()`/`refresh_digests()` 采用 manifest 声明值，缺省回落 10 MiB |

验收门槛核验（全过）：

- 「一个手写 Case + Replay 可被完整加载」：套件加载含清单校验、遥测清单一致性、环境基线存在性、锚点三字段一致、内容摘要验证；派生变体经真实摄取管线（`BatchIngestionService` + `ReferenceEventParser`）入库成功、零隔离记录。
- 「参数化派生变体共享 Ground Truth 且字段完整」：变体 GT 与基例逐字相等；占位符替换后全量无残留；未知参数与锚点不一致均拒绝。
- 双层 GT 必填由 Schema 强制（缺层拒绝）。

**架构关**：

- 独立抽包门禁：`capability_validation` 不 import 任何 threat_agent 业务模块（`test_architecture_dependencies.py` 新增规则，全量通过）。
- 依赖重量：包内第三方依赖仅 pydantic，其余为标准库；无 LangGraph/存储/网络依赖。
- 文档一致性：`softwareArchitecture.md` §7 模块树补齐 `agent_middleware` / `agent_eval` / `capability_validation` 三个独立包及抽包纪律约束（修正文档过期）。

**性能关**（Windows 开发机实测，合成规模曲线）：

| 事件数 | 加载 ms | 默认物化 ms | 变体派生 ms | 内容摘要 ms |
|---:|---:|---:|---:|---:|
| 1 000 | 35.2 | 13.6 | 14.9 | 1.7 |
| 5 000 | 41.9 | 73.0 | 72.9 | 4.4 |
| 20 000 | 139.9 | 309.3 | 307.4 | 8.9 |

结论：四项操作均线性（约 7~15 μs/事件）；PoC 规模（20 Case × 数百事件）整套加载亚秒级；步骤 02 真实攻击运行按 5 000 事件计，加载+物化约 115 ms/Case，相对后续 LLM 运行（秒~分钟级）可忽略。无优化必要。

全量回归：299 passed（新增 13 例验收 + 5 例对抗回归并入上述计数）。

存储决策（步骤 01 裁决）：测试资产直接进 git；二进制入 `replay/artifacts/`，单工件上限默认 10 MiB（manifest 可收紧）；对象存储为后置迁移，目录约定保证可移植。
