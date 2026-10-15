# 告警自动接入连接器 — 设计与分工

从态势感知源自动拉取未知文件告警并创建调查运行，替代人工在工作台粘贴告警 JSON。本文给出组件设计、运行策略、验收方式，以及平台侧与源端侧的职责边界。

## 1. 目标与非目标

目标：

- 定时调用 `query_alerts` 拉取新告警，映射后经既有 `RunService.start_alert` 建案，全流程进入现有审计。
- 用 fixture 告警源即可完整开发与测试；真实源端 handler 落地后零改动生效。

非目标：

- AI 调查过程中的告警查询（工具层暴露，见 [real-source-integration.md](real-source-integration.md) 缺口 3）。
- 源端 handler 的实现（缺口 1，源端侧职责）。
- 告警洪峰的排队与优先级管理（首版只做上限控制，洪峰策略后续按真实量级定）。

## 2. 架构位置

```
后台轮询 → query_alerts(SituationalAwarenessDataPort)
        → 告警映射器（UnknownFileAlert → intake 负载）
        → 去重状态存储
        → RunService.start_alert → 既有 AlertExecution 调查流程
```

连接器是数据 Port 的第三个消费方（既有：研判工具层、工作台手工建案），只依赖 Port 契约，不感知数据库或 IR。

关键取舍：

- **进程内直调 `RunService.start_alert`，不走 `/api/intake` HTTP 自调用。** 少一层网络与序列化，复用同一服务实例与租户上下文；代价是连接器与 `--serve` 进程生命周期绑定。独立进程部署属部署形态问题（design.md 已声明由接入环境决定），届时改走 HTTP 即可，组件不变。
- **去重状态用独立 SQLite 存储，不改 `SQLiteInvestigationRuntimeStore`。** 不侵入运行库 schema，测试隔离简单；代价是多一个状态文件，由 settings 指定路径。

## 3. 组件设计

### 3.1 告警映射器

`UnknownFileAlert` → `initialize_state` 接受的告警负载。映射规则：

| 契约字段 | 负载字段 | 缺失/不适配时的行为 |
|---|---|---|
| `file_hash`（sha256） | `File_hash` | 无哈希或非 sha256：跳过该告警，审计记 `skipped_unsupported_hash` |
| `file_path` | `File_path` | 缺失：跳过，记 `skipped_missing_field` |
| `host_ref` | `Sub_asset` | 必填，缺失同上 |
| `detected_at` | `discovery_time` | 缺失时调查回看窗从当前时间起算 |
| `pid` / `process_name` | `detail.context` | 可选；构造 `reported_process_chain` 线索供 Planner 验证 |
| `source_system` | `source` | 溯源标注 |

跳过不建案的告警同样记入去重状态，避免每轮重复跳过。

### 3.2 连接器服务

`case_management/application/alert_intake.py`，单轮执行流程：

1. 计算查询窗：起点 = 水位 − 重叠容忍，终点 = 当前时间。
2. `query_alerts`（按主机范围 + 时间窗 + 分页拉取，拉取上限 `ALERT_LIMIT`）。
3. 过滤已见告警（去重键命中）。
4. 剩余告警按 `detected_at` 升序处理，至每轮建案上限 `MAX_RUNS_PER_POLL` 为止。
5. 处理成功的告警记 seen；水位推进到**本轮成功处理告警中最晚的 `detected_at`**（不是当前时间）。

水位语义：未处理（超上限或建案失败待重试）的告警因重叠容忍仍在下一轮查询窗内，不漏单；重复拉取由去重吸收。

### 3.3 去重状态存储

SQLite，表结构：`(tenant_id, source_system, source_record_id)` 主键，记录 `first_seen`、`last_attempt`、`state`（seen / skipped / failed / abandoned）、`run_id`、`fail_count`。

### 3.4 调度与触发

- `--serve` 启动时按 `THREAT_AGENT_INTAKE_ENABLED` 决定是否启动后台轮询线程（与 `RunService` 线程模型一致），间隔 `INTERVAL_SECONDS`。
- 提供手动触发端点 `POST /api/intake/poll`，单轮执行并返回统计，用于演示、测试与验收。
- 默认关闭：每条告警触发一次完整 LLM 调查，启用是成本决策，由部署方显式打开。

### 3.5 观测与审计

`intake_alert_accepted`（含 run_id 与源告警引用）进入现有运行审计账本，工作台审计页与运行详情可见。轮询级事件（`intake_polled` 每轮统计、`intake_alert_skipped` 含原因、`intake_alert_failed`、`intake_poll_failed` 含错误分类）记录在接入状态存储的事件表——审计账本的 `audit_events` 对 `investigation_runs` 有外键约束，尚无运行的事件无法入账。这类事件随轮询报告经手动触发端点返回，也可经状态存储 `list_recent_events` 查询。

## 4. 失败语义

| 情形 | 行为 |
|---|---|
| `UnsupportedDataQuery` | 连接器自动停用，审计记一次；源端不支持告警查询时不应保持空转 |
| `DataQueryFailed` | 本轮放弃，水位不动，下轮重试 |
| 单条建案异常 | 记 failed，重试至多 3 次（跨轮），之后 abandoned 并审计 |
| 服务重启 | 水位与去重状态从存储恢复，不重灌历史告警 |

## 5. 配置

| 项 | 默认 | 说明 |
|---|---|---|
| `THREAT_AGENT_INTAKE_ENABLED` | false | 总开关 |
| `THREAT_AGENT_INTAKE_HOSTS` | （空） | 接入主机范围，逗号分隔；告警查询要求显式主机范围，未配置时连接器不启动 |
| `THREAT_AGENT_INTAKE_INTERVAL_SECONDS` | 300 | 轮询间隔；重叠容忍取 2× 间隔 |
| `THREAT_AGENT_INTAKE_MAX_RUNS_PER_POLL` | 5 | 每轮建案上限 |
| `THREAT_AGENT_INTAKE_ALERT_LIMIT` | 50 | 每轮拉取上限 |
| `THREAT_AGENT_INTAKE_STATE_PATH` | outputs/intake-state.sqlite | 去重与水位存储 |

## 6. 测试与验收

fixture 驱动（平台侧独立完成）：

1. 新告警建案，工作台运行列表可见。
2. 已见告警不重复建案；跳过类告警不重复跳过。
3. 超上限告警留待下轮，不漏单。
4. 重启后水位与去重状态恢复。
5. 查询失败不推水位；不支持时自动停用。
6. 无哈希/缺路径告警按规则跳过并审计。

集成验收（需真实源端）：真实告警一条 → 自动建案 → AI 调查取到真实活动数据 → 报告产出、审计全程可见。

## 7. 分工

分工线即 Port 契约：**Port 之上的消费与编排属平台侧，Port handler 的源端实现属源端侧。** 衔接点是 `assemble()` 注入处（[real-source-integration.md](real-source-integration.md) 缺口 1、2）。两侧可并行，fixture 使平台侧不阻塞在源端进度上。

| 职责 | 归属 | 交付物 |
|---|---|---|
| 告警映射器与字段规则 | 平台侧 | 映射器代码 + 规则表（3.1） |
| 连接器服务（轮询/去重/限流/失败语义） | 平台侧 | `alert_intake.py` + 去重存储 |
| serve 调度、配置项、手动触发端点 | 平台侧 | 接线与 `.env` 项 |
| 审计事件 | 平台侧 | 四类事件入账本 |
| 全链路测试 | 平台侧 | fixture 用例（第 6 节 1–6） |
| `query_alerts` 真实 handler | 源端侧 | 缺口 1 的告警域实现 |
| 字段对齐确认 | 源端侧 | 源端告警记录字段 ↔ 契约字段对照（`Sub_asset` 语义、进程线索可得性、哈希算法覆盖） |
| `assemble()` 注入与 serve 桥接 | 源端侧 | 缺口 1、2 |
| 上线参数决策 | 源端侧 | 启用时机、间隔与上限按真实告警量定 |
| 去重键加强 | 源端侧 | 若源端有告警聚合键，替换或加强 `source_record_id` 去重 |

## 8. 风险与后续

- `derive_case_id` 的并案语义（同文件同主机的重复告警是否归并到既有案件）在实现时验证；若不满足，同案多告警的去重加强列入后续。
- 告警洪峰超过每轮上限时只是延迟处理；若真实量级需要优先级或排队，另立需求。
- 多租户告警路由（按告警主机分配租户）首版不做，沿用默认租户，接入多租户时扩展查询与建案的租户传递。
