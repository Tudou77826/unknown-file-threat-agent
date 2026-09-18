# Agent Eval Framework — Design

## 1. 背景与现状

业务驱动有两层：

1. **SecAgent 自身需要评测**：合成参考数据（ground truth 由数据生成器注入）、L0–L3 难度阶梯、确定性校验器、typed 账本与运行事件持久化均已存在，但缺少跑批调度与指标聚合，文稿承诺的指标（接地发布率、越界拦截率、正确降级率、单案成本）没有数字产出。
2. **其他团队的项目需要同类设施**：任何「每案例多次调用 LLM 的端到端任务」都面临相同问题——并发慢、成本失控、结果不可比。要求框架本体与安全领域零耦合。

可复用资产盘点（截至 Feature 15）：

| 资产 | 评测角色 |
|---|---|
| 合成数据生成器 + L0–L3 配置 | 案例工厂与环境夹具，ground truth 内嵌 |
| `.sdd` 四场景方法论文档 | 新案例族的判定规则蓝本 |
| `ReportGroundingValidator` / 边界策略等确定性校验器 | 程序化打分器可直接 import |
| typed 账本 + SQLite 运行事件 | 轨迹级打分的观测底座（无需解析文本） |
| 双运行时（graph/middleware） | 仅作运行时收敛裁决的一次性实验变量（见 3.1 节），非常设维度 |

## 2. 开源选型结论

对三个候选路线的结论（2026-08 调研）：

**直接采用的依赖：只有基础件。** pydantic v2（契约）、pytest（CI 收集）、SQLite（产物落盘）。不引入任何重型评测框架作为运行时依赖。

**抄架构不引依赖：Inspect AI（UK AISI）。** 它是业界事实标准，但其价值密度对本场景有限——需要的是它的 Dataset/Solver/Scorer 三分法、Runner 职责边界和标准日志思想；它附带的沙箱体系、20+ 模型 provider 接入、async Solver 协议均用不上（本项目代码栈全同步、模型端点单一 OpenAI 兼容、案例执行需 in-process 调用真实网关）。因此**采纳其架构原则，自研轻内核**。

**抄方法论不写代码：**
- τ²-bench：终态判分优于文本判分、pass^k 可靠性度量；
- promptfoo：意图感知缓存与分层套件（smoke/nightly/full）组织方式;
- Langfuse/MLflow 共同验证的「先持久化完整运行产物、再离线打分」两段式。

**明确排除：** OpenAI Evals（官方已宣布 2026 年底关停）；LLM-as-judge 进回归门禁（仅后期人工校准用）；DeepEval/promptfoo 作为运行时（pytest/YAML 形态不适合 in-process 业务执行）。

**风险与复核条件**：轻内核把执行复杂度留在自己手里。若后续出现以下任一情况，重新评估将 Runner 桥接到 Inspect：需要沙箱执行类任务、多模型矩阵对比成为常态、或自研并发的稳定性/续跑能力达不到第 7 节性能预算。Runner 协议保持薄以维持该开放性。

## 3. 目标与非目标

### 目标

1. 框架包 `agent_eval` 与业务零耦合（复用 agent_middleware 的架构测试铁律），任何项目实现一个 Runner 协议即可获得全部设施。
2. 执行与打分解耦：运行产物一次落盘，打分/改打分/加指标全部离线秒级完成。
3. 几十案例 × 多次重复的评测在小时级完成（预算见第 7 节），smoke 子集分钟级进 CI。
4. 通过一次性的运行时收敛裁决实验，用数据确定 graph/middleware 二者的去留；裁决后的全部评测与 CI 只覆盖保留的运行时，并给出其首份基线报告。

### 3.1 运行时收敛原则

`runtime` 不是评测体系的常设被测维度：

1. **框架本体不感知运行时概念**。运行时差异属于 `RunRecord.config` 的一部分，框架只看到配置哈希，无任何特判；
2. 业务侧执行**一次性裁决实验**：同一案例集下 graph 与 middleware 成对全量比较（verdict 一致性、发布率、降级率、成本）。此实验是 Feature 15「并行验证期」的终点机制——其结论直接落实为运行时去留决策，替代该需求的"暂不切换、另行审批"挂起项；
3. 裁决后：保留的运行时成为**唯一**被测对象与 demo 运行路径，另一运行时退出生产线（代码归档而非并续维护）；demo 页运行时选择器随之收窄；
4. 此后如需引入新的编排实现，走同样的流程：先做一次性对照实验出数字，再裁决是否替换——框架不需要为此做任何改动。

### 非目标

- 不建设生产监控/漂移告警（OTel 与 Langfuse 接入为独立立项，通过 RunRecord 落盘格式解耦）。
- 不做数据集管理与标注平台；Case 定义即代码，进 git 版本化。
- 不在本 Feature 内扩展勒索/数据泄露新案件族（沿用现有 C2 两族数据）。

## 4. 总体方案：三件套正交切分 + 两段式流水线

```
┌─ 项目侧（每个项目各写一份）────────────────┐
│  CaseFactory（造 Case 列表）                │
│  TaskAdapter: run_case(case) -> RunRecord  │
│  Scorer 集（多数是确定性函数）               │
└──────────────┬─────────────────────────────┘
┌─ 框架侧（全公司共享）──────────────────────┐
│  Runner：并发调度 · 限流 · 幂等续跑 · 落盘   │
│  ScoreRunner：离线批量打分                  │
│  Reporter：聚合矩阵 · 对比 · 回归标记        │
└───────────────────────────────────────────┘
```

### 4.1 核心契约

```python
class Case(StrictModel):
    case_id: str                     # suite 内唯一
    suite: str                       # 数据集版本标识（版本化进 git）
    task_input: dict[str, Any]       # 交给被测 Agent 的输入
    environment: dict[str, Any]      # 夹具描述：随案例提供的文件/种子数据清单
    ground_truth: dict[str, Any]     # 键约定由 scorer 定义（如 expected_verdict）
    tags: set[Literal["smoke", "full", "adversarial", "regression", ...]]

class RunRecord(StrictModel):
    run_id: str                      # = f"{case_id}#{config_hash}#{epoch}"，天然幂等键
    case_ref: str                    # 关联 Case
    config: dict[str, Any]           # 完整可复现参数：model/runtime/k 序号/温度…
    status: Literal["ok", "error", "timeout"]
    metrics_raw: dict[str, float]    # 迭代数/tool_calls/tokens/时长（执行期已得）
    artifacts: dict[str, str]        # transcript.json / typed_ledger.json /
                                     # events.jsonl / report.json 相对路径
```

设计要点：

- `RunRecord.run_id` 以 `(case, config_hash, epoch)` 构成幂等键：断点续跑按此跳过已完成项；重复跑同一 suite 默认命中已有记录（省钱），传 `--fresh` 强制重采样。pass^k 即 k 个不同 epoch 的独立采样，天然绕开缓存失效问题。
- 产物优先于聚合值：transcript、typed ledger、事件流全量落盘，打分器永远面对原始产物而不是预先摘要。

### 4.2 Runner 协议（框架只认这一个口）

```python
class EvalTask(Protocol):
    def run_case(self, case: Case, *, epoch: int, workdir: Path) -> dict:
        """执行一个案例；返回 metrics_raw，产物写入 workdir。"""
```

实现要点：线程池并发（业务栈为同步代码，不做 asyncio 改造）；共享令牌桶限流（RPM/TPM 双维配置）+ 429 全抖动指数退避；每 worker 独立工作目录（环境夹具复制到 `workdir/env/`，消除 SQLite 等共享资源竞争）；崩溃后重跑命令自动从已完成 run 续起。

### 4.3 打分协议（两段式的第二段）

```python
class Scorer(Protocol):
    name: str
    def score(self, record: RunRecord, case: Case) -> Score:  # value + 附注
```

三级 scorer（可靠性阶梯）：确定性函数 → 统计聚合（pass^k 在 Reporter 层做，不在单 Scorer 里）→ model-judge（本期只预留角色位，不实现）。所有 SecAgent 打分器直接复用产品内校验器（接地校验、边界码断言），保证测的就是交付物本身。

### 4.4 分层套件

由 `Case.tags` + CLI 参数组合实现，框架不设固定层级：`--tags smoke --limit-per-suite 6` 即为 PR 门禁子集；`--all --epochs 5` 为 nightly 全量。门禁阈值由调用方在 CI 配置里声明，框架只如实报告。

## 5. 自研 / 复用边界总表

| 部分 | 决策 | 来源 |
|---|---|---|
| 契约三件套、日志格式 | **自研**，抄 Inspect Sample/EvalLog 思想 | Inspect AI |
| 并发 Runner、幂等续跑 | **自研**（同步栈线程池形态） | Inspect 执行引擎思路 |
| RPM/TPM 限流 + 抖动退避 | **自研**（~百行） | 业界网关通行做法 |
| pydantic / pytest / SQLite | **直接使用** | 已在栈内 |
| pass^k / 终态判分 | **方法论采纳**，Reporter 层实现 | τ²-bench |
| 缓存按意图开关 | **机制采纳** | promptfoo |
| 执行/打分两段式 | **架构采纳** | Langfuse/MLflow cookbook 共识 |
| verifier 复用 | **直接使用业务侧校验器** | 本仓库 |
| judge / sandbox / OTel | **不做**（接口留位） | — |

规模预估：框架本体 ≤ 1200 行（含测试除外），其中一半是契约与协议定义。

## 6. SecAgent 集成形态（首个消费者）

- **CaseFactory**：从合成数据生成器枚举「案件族 × L0–L3」，malicious/benign ground truth 直取生成参数；一期覆盖现有 C2 两族共 8 个基础案例。
- **TaskAdapter**：per-run 复制活动库 → 经真实 gateway/boundary/report 流水线执行（运行时归属只出现在 config 中，适配器同一份代码服务两种编排）→ 收集账本/事件/报告写入 workdir。
- **一期 Scorer 集**（全部确定性）：VerdictMatch（分级距离计分）、PublicationStatus（grounded/fallback 正确性）、DegradationCorrectness（L0/L1 下不得出确认级结论）、BoundaryInterception（对抗标签案例的拦截与纠正）、CostEfficiency（迭代/tool_calls/tokens）。
- **入口**：`python -m threat_agent.bootstrap.eval_cli …`（落业务侧），框架侧保持纯库。

## 7. 性能预算（验收门槛之一）

| 场景 | 目标上限 |
|---|---|
| smoke 子集（≤12 案例 × 单 epoch × 单运行时） | ≤ 5 分钟 |
| 全量 50 案例 × k=3，单运行时（150 runs，稳态形态） | ≤ 1 小时 |
| 运行时收敛裁决实验（50 案例 × k=3 × 成对两运行时，仅一次） | ≤ 2 小时 |
| 存量产物重打分 | 秒级（无 LLM 调用） |

约束条件如实声明：上述预算以服务商 RPM/TPM 配额允许 ≥12 并发为前提；限流触发时按退避自动拉长，报告须标注实际并发与被限流次数。稳态评测永远是单运行时口径；双运行时仅存在于裁决实验这一例外。

## 8. 验收门槛

1. `agent_eval` 不 import 任何业务模块（新增架构断言测试）；
2. 用假 TaskAdapter（睡眠模拟 LLM 延迟）验证：并发加速比、限流生效、kill 后重跑仅补未完成项；
3. 两段式验证：删除全部打分缓存后重打分零 LLM 调用；同 suite 重跑默认命中、`--fresh` 重采样；
4. 运行时收敛裁决：C2 两族 × L0–L3 × 两运行时 × k=3 出具带明确去留建议的裁决报告；裁决落实后再对保留运行时出具单运行时基线（两份报告）；
5. 存量全量测试继续通过（当前 146 项）。

## 9. Harbor 吸收结论（2026-09-18 调研增补）

调研对象：[Harbor](https://harborframework.com/)（Terminal-Bench 团队，Apache-2.0，5.4k stars，
docs 见 [docs.harborframework.com](https://docs.harborframework.com/)）。结论：**不引入 Harbor 作为评测底座，
吸收其任务封装与重打分设计**；方法论基准维持 Inspect AI（pass^k、三件套正交切分，本设计 §4 已对齐）。

### 9.1 不引入的理由

- Harbor 的执行模型是「被测 Agent 在每案例一个 Docker 容器内运行，验证脚本在同一容器内读
  `/logs/verifier/reward.txt`」；我们的被测对象是进程内 FastAPI + LangGraph 服务与 SQLite 合成遥测库，
  逐案例容器化只会增加运维面而不改变评测语义。
- Harbor 的强项（CLI Agent 适配器矩阵、云沙箱横向扩展、RL rollout 导出）都不在当前需求面内；
  数据不出域约束下云沙箱一票否决。
- 自研 Runner 的规模预算（§5 ≤1200 行）远小于适配 Harbor 的胶水与容器镜像维护成本。

### 9.2 吸收项（落入本设计对应章节）

| Harbor 概念 | 吸收方式 |
|---|---|
| 任务三件封装：`instruction.md + task.toml + environment/ + solution/ + tests/` 目录约定 | Case 目录约定：`evals/cases/<case_id>/` 下 `case.yaml`（题面输入+ground_truth）、`env/`（种子与数据等级）、`solution/`（参考研判：期望结论、期望查询路径、期望 ATT&CK 映射）、`scorer.py`（可选覆盖）——Case 定义即代码进 git 的物理形态 |
| `reward.json` 多维奖励 | Score 从单值+附注扩展为**命名维度字典**（verdict/publication/boundary/cost…），Reporter 按维度聚合并支持总分加权配置 |
| **regrade**（更新验证器后对已录产物重打分，不重跑 Agent） | 强化两段式：ScoreRunner 以 `--regrade` 为一等入口，打分只依赖 workdir 产物（本设计 §4.3 已有此语义，吸收其命名与 CLI 地位） |
| `dataset.toml` 清单 + `dataset@version` 版本钉住 | suite 清单文件 + 版本钉住语法进入 eval CLI（`--suite secagent-evals@<git-ref>`）；私有 git 仓库即数据源，无中心 registry |
| 多步任务的 milestone 评分（`steps/`） | 里程碑评分概念：按证据门/报告/处置三个阶段给分段判定，二期实现 |
| solution/ 参考解 | 参考研判成为出题必备件：ground truth 不只是结论，还包括期望取证路径，供轨迹级 scorer 与人工出题复核 |

### 9.3 横向对比速记（同日结论）

- [Inspect AI](https://inspect.aisi.org.uk/)（UK AISI）：Task/solver/scorer + pass^k，可自托管，方法论最成熟——**维持为基准**，本设计已吸收其三件套与 pass^k；
- [DeepEval](https://deepeval.com/) / [promptfoo](https://www.promptfoo.dev/)：pytest/YAML 式 CI 门禁与 RAG 指标强，但打分器生态偏通用 LLM 指标，与「复用产品内校验器」原则重叠度低——不引入；
- LangChain [agentevals](https://github.com/langchain-ai/agentevals)：轨迹严格匹配等小型评测函数库——其轨迹比对思路可在一期轨迹级 scorer 里借鉴，不作为依赖；
- LangSmith / Braintrust 评测：云托管优先，违反数据不出域——排除；
- [Anthropic 评测方法论](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents)：回归/能力/生产轨迹三分类与本设计 smoke/full/adversarial 标签同构，无新增动作。
