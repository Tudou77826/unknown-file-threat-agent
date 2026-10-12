# Feature 19 — Verification

## 技术覆盖轴首轮评测（2026-09-30，[validation-baseline-2026-09-30.md](validation-baseline-2026-09-30.md)）

`--suite validation` 直连 F16 评测内核：5 案例（2 手写 + 3 靶场）全链真实 LLM 执行 5/5 ok。
检出方向 100%、发布接地 100%；三个靶场案例置信级保守（suspicious vs 期望 confirmed），
按 2026-09-30 复核裁决记录：**原验收要求未达到；已发现关键采集缺口（文件写入事件丢失），
暂不能据此认定是模型问题，待补采对照验证**——不改为通过。补齐后是否足够确认级判定，仍需核对
实际证据后按"事实→AI 可见→合理判断"三步程序校准。同期修正三项评分缺陷（空评分空真算通过、
epoch 均值累积错误、边界评分器无判定 fail-open）并入库回归测试；五案例事实描述按实际行为修正，
预期判定全部冻结待人工确认。


## 步骤 02 桌面阶段（已验收 2026-09-29，靶场阶段待环境）

交付物：

- 技术选择目录 [attack-catalog.md](attack-catalog.md)：12 恶意（11 新剧本 + 既有 c2-malicious-elf）+ 6 良性（5 新 + 既有 c2-benign-baseline），每条恶意刻意配良性对照；含排除记录（T1055.001 非 Linux、T1136.001 无 Canonical 事件族、T1210 跨主机、脚本类载荷降级）。
- `attack_lab/`：采集器（auditd 规则 + collect.sh 编排：窗口标注、ps/ss/rpm/包归属快照、工作区归档与哈希清单）、16 个剧本（run.sh + case.json GT 草案）、`settle_case.py` 沉淀管线、README 运行手册。
- `capability_validation/projection_auditd.py`：步骤 01 预留的投影转换器——auditd 行 → 探针范围信封 → canonical 事件；进程身份稳定化（首见 exec 时间 + ps 启动时间）、ppid 父链派生、/etc/systemd/system 写入派生 systemd_event、sockaddr 四元组解析。
- `ReferenceEventParser` 新增 `file_event` 分支（§2 文件事件此前落 ExtensionActivity，丢失 FileActivity 结构）。

### 严格验收（2026-09-29，功能 / 架构 / 性能三关）

**功能关：对抗性探测 5 项发现，全部修复并转回归测试**（`tests/test_capability_validation_step02.py`，8 例）：

| 发现 | 处置 |
|---|---|
| 采集规则故意采集 EACCES/EPERM 被拒操作，但投影不查 success——被拒的创建/连接成为**幻影证据**（AI 侧最大的正确性风险） | 分类器统一 success=yes 门禁：被拒 exec/file/connect/特权 syscall 一律不产事件 |
| 一个审计事件的**多条 PATH 记录在按类型分组时互相覆盖**——rename 静默退化为 create 且丢失 renamed_from | 分组结构改为 rtype→list；rename 按 nametype（DELETE/CREATE）配对，与记录顺序无关 |
| 反证 observed_at 用沉淀当天日期，非采集窗口（重放语义错误） | 反证时间戳统一为采集窗口末毫秒 |
| GT 与 expected_ai 可互相矛盾（benign 真值 + malicious 预期被接受） | TestCase 增加模型级一致性校验：expected_ai.verdict 必须与文件级判定蕴含一致（malicious/abused→malicious，benign→benign） |
| settle 从包外 import 私有函数 `_iso` | 独立实现，包公共面不变 |

验收门槛核验：auditd 分类（进程/文件/网络/命令，EXECVE 引号/十六进制双语义，跨空格 msg 提取）、投影（hash 锚点、父链派生、persistence 派生）、**端到端**（合成 bundle → settle → 产出 Case 通过套件全量校验，窗口外记录剔除，反证含负证据且时间戳在窗口内）。

**架构关**：

- 独立抽包门禁通过：`projection_auditd` 仅依赖标准库 + 包内模块（grep 核验 + 门禁测试）；
- `settle_case.py` / attack_lab 为靶场工具链，仅 import 包公共 API，不进 src 分发面；
- `ReferenceEventParser` 扩展属 data_foundation 内部增量，无边界破坏；已知限制（EXECVE 分片参数、ps lstart 本地时区、被拒操作丢弃）写入 attack_lab/README。

**性能关**（合成规模曲线，Windows 开发机实测）：

| 审计事件组 | 日志行 | 解析 ms | 投影 ms | settle 全链 ms（含 IO+摘要） |
|---:|---:|---:|---:|---:|
| 1 000 | 2 001 | 19.9 | 9.3 | 277 |
| 5 000 | 10 001 | 115.7 | 55.7 | — |
| 10 000 | 20 001 | — | — | 694 |
| 20 000 | 40 001 | 453.0 | 226.3 | — |

结论：解析+投影约 17~23 μs/行，严格线性；真实攻击窗口（数千至数万行）单 Case 沉淀亚秒级，远低于靶场执行节奏，无优化必要。

全量回归：307 passed。

靶场阶段待办（依赖环境，见 attack_lab/README.md 前置条件表）：部署采集器与剧本 → 逐 Case 真实执行 → settle → GT 人工复核 → 入正式套件；规则侧告警与受理回执对应关系人工记录（步骤 03 采集建好后自动化）。步骤 02 验证门槛中「Replay 重放结果稳定」在靶场 Case 入库后复验。

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

## 靶场阶段验收记录与阶段性收口（2026-10-12，用户批复 1-7/9 同意、10 不做）

### 1. 本阶段完成项（证据在案）

- 步骤 01（Case 与 Replay 契约）、步骤 02 桌面阶段：沿用 2026-09-29 已验收记录。
- **步骤 02 靶场阶段（本次补齐）**：29 案按采集协议 v2 在靶机真实执行重采
  （prepare/attack 分段、C2 非回环 198.51.100.50、端点基线按案、投放路径生产化、
  编译与脚手架出窗）；三轮现场修复记录见 `attack_lab/OPTIMIZATION_CHECKLIST.md`
  （2026-10-10~12 条目，提交链 dfc9f33→a9ca373）。
- 数据质量：四类残留（secval 字样 / lab 主机名 / 回环 C2 / 窗口内编译链）扫描全零；
  三轮数据复核（答案泄露→靶场痕迹→证据缺口）全部闭环，逐轮有根因分析与修复提交。
- 沉淀管线升级：认证域查询工具（query_authentication_activities 全链路）、系统文件
  内容采集、stat 快照（含 tar 元数据兜底）、端点批准基线按案化、网络观测计数。
- 判定证据链验证（抽样）：t1548 uid=65534/euid=0 双值、t1552 真实窃取+回传回执、
  chain-001 载荷派生进程树归因、t1136 passwd 内容含 UID 0 账号、t1070 mtime<birth
  物理矛盾——全部进入 AI 可查面并被模型正确使用。

### 2. AI 侧评测数字（r12，epochs=2）

| 面 | 运行 | dist | 方向正确率 |
|---|---:|---:|---:|
| 恶意全量（21 案） | 40 | 0.790 | 92% |
| 良性·非镜像（4 案） | 8 | 0.800 | 88% |
| **当前能力面（合并）** | **48** | **0.792** | **92%** |
| 良性·镜像（延后黄区） | 10 | 0.280 | 0% |

验收线（dist≥0.75 / 方向≥85%）：当前能力面双双通过；整体 0.71/0.79 的缺口完全由
延后项构成。demo 套件回归：dist 0.84 / match 1.0 / side 1.0 / 边界 1.0 / pass^k 1.0
（较基线 0.82 提升不降）。镜像面延后系 2026-10-12 用户裁决：当前环境无权威文件/端口
白名单工具，模型不轻信自建基线在生产语境是正确直觉，黄区对接安全系统后自然消解。

### 3. 对照 requirements §5 的逐项状态

| 验收条件 | 状态 |
|---|---|
| 问题①标准攻击下规则覆盖多少 | **未答**——规则检测结果需外部态势感知系统采集，未接入 |
| 问题②自主攻击下规则覆盖多少 | **未启动**——AI 自主攻击未生产，且依赖①的规则侧基线 |
| 问题③规则漏检后 AI 补回多少 | **部分可答**——AI 研判质量有硬数据（上表）；补漏率分母（规则漏检集）切不出 |
| 10~20 Case 参数化 Replay | **超额**——29 案 v2，参数化回放管线成熟 |
| 规则与 AI 结果统一 Case 结构 | **半成**——AI 侧全通；规则侧无数据源（expected_rule 回执字段已预留） |
| Scorer 三类指标报表 | **半成**——AI 指标齐全；规则指标空；"规则覆盖+AI 增量"无法计算 |

### 4. 挂起项与解锁条件

| 挂起项 | 解锁条件 | 届时动作 |
|---|---|---|
| 规则侧结果采集 | 黄区对接态势感知系统 | 经 expected_rule 受理回执采集规则命中，补齐①③作答与三类报表 |
| AI 自主攻击 | 同上（价值判定依赖规则侧基线） | 生产非固定路径攻击数据，作答② |
| 镜像良性误报面 | 黄区权威白名单工具 | 反证事件 schema（approved_endpoint 等）换权威数据源，管线不动 |

### 5. 结论

**Feature 19 状态＝阶段性验收通过**（AI 侧能力验证闭环、29 案 v2 数据资产达标、
质量整改有据）；完整闭环待黄区环境，剩余项与解锁条件如上，无隐藏项。

尾项归属：t1552/chain-001 v2 GT 复核＝用户（进行中）；t1574 补 .so 工作区副本＝
下次实验室行程（prepare 已改妥待部署）；恶意保守半级＝模型侧迭代，本阶段不做。
