# Linux 未知文件威胁研判 Agent：内部分析与 Skill 设计方案

> 版本：v1.0  
> 日期：2026-07-28  
> 目的：解释 Agent 内部如何读取证据、如何决定下一步、如何拆分 Skill、如何构建证据图并最终得到攻击链。  
> 范围：业务 Agent 内部设计；不设计底层 RAG、MCP、模型服务和通用 Agent 基座。

## 1. 内部设计目标

Agent 接到一个未知文件案件后，不是直接生成分析报告，也不是按固定规则判断：

```text
curl + cron + 外部 IP = 后门
```

Agent 应执行一个受证据驱动的连续调查过程：

```text
建立案件
→ 理解现有证据
→ 提出多个解释
→ 找到最关键的证据缺口
→ 选择下一项分析或查询
→ 更新案件状态
→ 必要时跨文件、扩时间、跨主机
→ 建立事件图
→ 从图中提取行为路径
→ 评估候选攻击路径
→ 输出 Verdict
```

核心原则：

1. 始终以未知文件为调查锚点。
2. 先证明事实，再解释攻击。
3. 先使用已有三张表，再按需补证。
4. 下一步由当前证据决定，不写死完整流程。
5. 允许多个候选假设并存。
6. 同时寻找攻击证据、反证和合法解释。
7. 不能因数据未采集而声称行为没有发生。
8. 每个关键结论必须引用证据。

## 2. Agent 内部总体结构

```text
┌────────────────────────────────────────────┐
│ A. 案件入口与状态管理                      │
│ case / scope / hypotheses / gaps / budget │
└────────────────────┬───────────────────────┘
                     ↓
┌────────────────────────────────────────────┐
│ B. 证据接入与质量评估                      │
│ 三张表 / 补充数据 / 来源 / 覆盖 / 去重      │
└────────────────────┬───────────────────────┘
                     ↓
┌────────────────────────────────────────────┐
│ C. 三层专项分析                            │
│ 静态与二进制 / 终端系统 / 网络传输          │
└────────────────────┬───────────────────────┘
                     ↓
┌────────────────────────────────────────────┐
│ D. 调查规划循环                            │
│ 当前问题 → 下一步 → 获取结果 → 更新假设     │
└────────────────────┬───────────────────────┘
                     ↓
┌────────────────────────────────────────────┐
│ E. 三类场景评估                            │
│ 后门 / 数据窃取 / 勒索                     │
└────────────────────┬───────────────────────┘
                     ↓
┌────────────────────────────────────────────┐
│ F. 时间线、事件图和路径重建                 │
│ nodes / edges / paths / gaps              │
└────────────────────┬───────────────────────┘
                     ↓
┌────────────────────────────────────────────┐
│ G. Verdict 和报告                          │
│ 结论 / 证据 / 反证 / 缺证 / 影响            │
└────────────────────────────────────────────┘
```

## 3. Agent 必须维护的内部状态

Agent 不能只依赖对话上下文，需要维护结构化案件状态。

### 3.1 `case_scope`

记录当前调查边界：

```json
{
  "case_id": "case-001",
  "anchor_file": {
    "path": "/tmp/.cache/update",
    "sha256": "abc",
    "type": "ELF"
  },
  "anchor_host": "web-01",
  "anchor_time": "2026-07-28T10:23:41+08:00",
  "current_time_window": {
    "start": "2026-07-28T10:08:41+08:00",
    "end": "2026-07-28T10:53:41+08:00"
  },
  "hosts_in_scope": ["web-01"],
  "files_in_scope": ["/tmp/.cache/update"],
  "scenario_focus": []
}
```

### 3.2 `known_facts`

只保存能够被证据支持的事实：

```json
{
  "fact_id": "F-001",
  "statement": "主机 web-01 发现未知 ELF /tmp/.cache/update",
  "evidence_ids": ["E-CDE-001"],
  "status": "observed"
}
```

### 3.3 `hypotheses`

保存候选解释，而不是立即确定唯一攻击故事：

```json
[
  {
    "hypothesis_id": "H-001",
    "statement": "未知文件由 WebShell 下载并作为后门执行",
    "status": "open",
    "supporting_evidence": [],
    "contradicting_evidence": [],
    "required_evidence": [
      "文件创建进程",
      "Web请求",
      "实际执行事件",
      "进程网络连接"
    ]
  },
  {
    "hypothesis_id": "H-002",
    "statement": "未知文件由合法发布系统部署",
    "status": "open",
    "supporting_evidence": [],
    "contradicting_evidence": [],
    "required_evidence": [
      "发布记录",
      "软件包来源",
      "历史同类任务"
    ]
  }
]
```

### 3.4 `evidence_gaps`

记录当前缺什么，以及为什么重要：

```json
{
  "gap_id": "G-001",
  "question": "未知文件是否真实执行？",
  "required_evidence_type": "process_exec",
  "priority": "critical",
  "reason": "不证明执行就不能把后续行为归因到未知文件",
  "query_candidates": ["query_process_events", "query_audit_events"]
}
```

### 3.5 `investigation_queue`

记录下一步候选任务：

```json
[
  {
    "task_id": "T-001",
    "goal": "证明未知文件是否执行",
    "tool_or_skill": "analyze-linux-endpoint-behavior",
    "arguments": {
      "host_id": "web-01",
      "file_path": "/tmp/.cache/update",
      "start": "...",
      "end": "..."
    },
    "expected_information_gain": "high",
    "cost": "low"
  }
]
```

### 3.6 `evidence_graph`

持续保存实体和关系，后续攻击链直接从图中产生。

### 3.7 `coverage_state`

记录数据是否采集、是否完整：

```json
{
  "process_events": "available",
  "file_read_events": "not_collected",
  "network_process_attribution": "partial",
  "history_retention_days": 7
}
```

## 4. 统一证据结构

任何来源的数据都先转换为证据对象：

```json
{
  "evidence_id": "E-PROC-001",
  "evidence_type": "process_exec",
  "source": "endpoint_process_events",
  "source_event_id": "raw-9981",
  "observed_at": "2026-07-28T10:21:03.120+08:00",
  "host_id": "web-01",
  "container_id": null,
  "subject": {
    "type": "process",
    "id": "web-01:boot-a:5312:1753678863"
  },
  "action": "executed",
  "object": {
    "type": "file",
    "path": "/tmp/.cache/update",
    "sha256": "abc"
  },
  "attributes": {
    "cmdline": "/tmp/.cache/update --silent",
    "uid": 33
  },
  "raw_reference": {
    "source": "process-event-store",
    "record_id": "raw-9981"
  },
  "reliability": "high",
  "observation_status": "observed"
}
```

### 4.1 证据状态

- `observed`：来源直接记录。
- `correlated`：通过稳定实体连接多个直接记录。
- `inferred`：大模型根据多条证据推断。
- `unknown`：当前无法确定。
- `conflicting`：证据相互冲突。

### 4.2 缺失状态

- `not_observed`：覆盖完整但没有观察到。
- `not_collected`：没有采集。
- `not_available`：过期或当前不可用。
- `not_attributable`：有事件但不能绑定到目标。
- `conflicting`：来源冲突。

## 5. 分析顺序：先做什么，后做什么

下面不是固定攻击规则，而是通用调查优先级。某一步出现强线索时，Agent可以插入其他调查任务。

### 第 0 步：建立案件和校验输入

读取：

- `T_FILE_DETAILS`
- `T_PROCESS_CHAIN_HASH`
- `T_abnormal_event_TO_REPORT_OS`

执行：

1. 确定未知文件路径、Hash、主机和告警时间。
2. 解析 `DETAIL` 进程链。
3. 合并进程链 Hash 信誉。
4. 读取已有异常事件。
5. 统一时间、主机、容器和用户字段。
6. 评估字段完整性和来源可靠性。
7. 建立初始证据对象。

输出：

- `initial_case_state`
- 初始事实。
- 初始数据覆盖。
- 解析警告。

为什么最先做：

如果主机、时间、目标文件或进程链语义不清楚，后续查询会扩大错误范围。

### 第 1 步：理解文件并提取调查线索

分析内容：

- 现有 CDE 结论。
- 文件真实类型和基础元数据。
- ELF/脚本结构化结果。
- 命令、路径、IP、域名和URL。
- 可能的文件操作、网络、持久化、归档或加密能力。
- 软件包、签名和合法来源。

输出不是“恶意/安全”，而是：

```json
{
  "capability_leads": [
    {
      "lead": "可能访问 /etc/cron.d",
      "source": "static_string",
      "confidence": "medium",
      "next_queries": ["query_file_events", "query_persistence"]
    }
  ],
  "benign_context": [],
  "limitations": []
}
```

### 第 2 步：首先证明文件是否执行

优先级最高。

分析：

- `REALTIME_TYPE` 是否只是触发类型，还是有执行证据。
- 进程 exec 事件。
- auditd `EXECVE/SYSCALL/PATH`。
- 解释器是否打开并执行脚本。
- `/proc` 或EDR进程实体。
- 文件是否只是创建、加载或映射。

输出：

```text
not_executed
execution_observed
execution_likely
execution_unknown
```

关键要求：

- 只有文件存在不能证明执行。
- 只有进程名相同不能证明执行。
- 使用主机 + Boot ID + PID + 启动时间绑定进程。

如果确认没有执行：

- 继续调查落地来源和是否存在其他文件执行。
- 不把未知文件未发生的网络或文件行为归因给它。

### 第 3 步：向前追溯来源

从未知文件反向查询：

1. 谁创建、写入或重命名了文件。
2. 创建进程由谁启动。
3. 父进程属于 Web、SSH、cron、systemd、容器还是发布系统。
4. 是否存在下载 URL、上传请求或解压来源。
5. 是否存在关联登录会话。
6. 是否有合法发布、软件包或运维记录。

典型分支：

```text
php-fpm/nginx/apache/tomcat
→ 查询 Web/WAF/应用日志

sshd/bash/sudo
→ 查询认证、来源IP、账号和会话

cron/systemd
→ 查询任务内容、创建者和首次出现时间

deployment/package manager
→ 查询发布、软件包和变更记录

container runtime
→ 查询镜像、Pod、挂载和Kubernetes审计
```

输出：

- `provenance_path`
- 已确认入口。
- 候选入口。
- 合法来源反证。
- 入口缺失证据。

### 第 4 步：向后追踪真实行为

以目标进程实体为中心查询：

- 子进程。
- 创建、读取、修改、重命名和删除文件。
- 权限和用户变化。
- 服务和持久化变化。
- 网络连接和DNS。
- 容器和其他主机访问。

此步骤只归纳现场行为，不立即解释为攻击。

输出示例：

```text
10:21:03 未知ELF执行
10:21:05 连接198.51.100.20:443
10:21:08 写入/etc/systemd/system/update.service
10:21:10 执行systemctl enable update.service
```

### 第 5 步：启动三个场景的证据评估

三个场景可以同时打开。

#### 后门证据问题

- 是否提供命令执行或远程控制。
- 是否反向连接、监听或周期回连。
- 是否隐藏、伪装、劫持或删除后运行。
- 是否建立持久化。
- 是否修改账号、SSH key和权限。
- 是否继续控制其他主机。

#### 数据窃取证据问题

- 是否发现或读取敏感数据。
- 是否数据库导出。
- 是否归集、压缩、加密和暂存。
- 是否存在对应出站传输。
- 是否使用窃取凭据跨主机。
- 是否删除暂存或清理痕迹。

#### 勒索证据问题

- 是否高频批量操作文件。
- 是否统一重命名或内容随机化。
- 是否停止服务和安全能力。
- 是否删除快照或备份。
- 是否生成勒索信。
- 是否影响共享存储或其他主机。

场景Skill不能根据一个关键词直接确认场景，而应返回：

```text
supported
partially_supported
possible
contradicted
not_observed
insufficient_data
```

### 第 6 步：跨文件扩展

触发条件：

- 未知文件由脚本释放或下载。
- 未知进程创建其他可执行文件。
- 配置引用其他文件。
- 发现压缩包、暂存文件或勒索信。
- 发现其他文件参与同一进程链。

扩展方式：

```text
目标文件
→ 创建者文件
→ 释放文件
→ 配置文件
→ 输入/输出数据文件
```

每扩展一个文件，都要记录：

- 为什么加入范围。
- 与锚点文件的关系。
- 关系证据。
- 是否需要静态分析。

### 第 7 步：跨时间扩展

触发条件：

- 文件创建早于当前窗口。
- 登录会话更早开始。
- C2或破坏行为持续到窗口之后。
- 存在cron/systemd周期执行。
- 当前IOC可能历史出现。

推荐顺序：

```text
局部分钟窗口
→ 小时级案件窗口
→ 7天或产品保留期历史
```

历史查询对象：

- Hash。
- 路径。
- 命令。
- 账号。
- C2。
- 持久化。
- 勒索信。
- 文件操作模式。

### 第 8 步：跨主机扩展

触发条件：

- 源主机对其他主机建立远程会话。
- 相同Hash或C2出现在其他主机。
- 相同账号、SSH key或Token被使用。
- 相同镜像或共享存储受影响。
- 多主机出现相同勒索行为。

必须记录：

- 扩展目标主机的原因。
- 匹配维度和强度。
- 来源证据。
- 是否存在常见共享基础设施的替代解释。

一个普通IP、文件名或命令不能单独证明同一攻击。

### 第 9 步：构建证据图

将所有已确认实体和关系写入图。

### 第 10 步：从证据图生成路径

分别生成：

1. 已观察行为路径。
2. 候选攻击路径。
3. 缺失步骤。
4. 备选合法路径。

### 第 11 步：形成 Verdict

综合：

- 是否有入口或来源。
- 是否证明执行。
- 是否有执行后行为。
- 是否跨来源互相印证。
- 是否有合法解释。
- 数据覆盖是否充分。
- 攻击链关键步骤是否缺失。

## 6. 下一步由什么决定

Agent每轮选择“信息增益最高”的问题，而不是读取所有日志。

建议优先级：

```text
能否改变Verdict的关键问题
> 能否证明执行/归因的问题
> 能否区分攻击与合法解释的问题
> 能否确定影响范围的问题
> 只增加背景但不改变结论的问题
```

选择下一步时评估：

```json
{
  "question": "外部连接是否由未知文件产生？",
  "impact_on_verdict": "high",
  "available_tool": "query_network_events",
  "data_coverage": "available",
  "query_cost": "low",
  "priority": 1
}
```

停止条件：

- 已回答案件核心问题。
- 主路径关键步骤均有证据或明确缺证。
- 新查询不能显著区分候选假设。
- 达到时间、数据或查询预算。
- 数据源不可用。
- 继续扩展将超出授权范围。

## 7. 什么交给大模型，什么交给确定性代码

### 7.1 大模型负责

- 理解案件语义。
- 提出候选假设。
- 判断当前最关键问题。
- 选择下一项查询或Skill。
- 根据新证据更新解释。
- 识别替代解释和反证。
- 决定跨文件、跨时间、跨主机。
- 解释行为路径和候选攻击路径。
- 形成可读研判报告。

### 7.2 确定性代码负责

- JSON和日志解析。
- Schema校验。
- auditd同事件记录合并。
- 时间和时区转换。
- Hash计算和比较。
- 主机、Boot、PID和启动时间实体关联。
- 文件rename链处理。
- 去重。
- 图节点和边写入。
- 查询限制和权限。
- 输出结构校验。

### 7.3 不能交给大模型猜测

- 原始日志不存在时编造事件。
- 仅凭PID认定同一进程。
- 仅凭时间接近认定因果。
- 仅凭字符串认定现场行为发生。
- 仅凭IOC命中确认攻击。
- 仅凭上游置信度产生最终Verdict。

## 8. Skill 如何拆分

Skill不是每个函数一个Skill。Skill应封装可以独立触发、具有明确输入输出、需要专业工作流的能力。

推荐运行时采用“一个主Skill + 四个专项Skill”。

### 8.1 主Skill：`investigate-unknown-file-threat`

职责：

- 接收初始案件。
- 建立Agent内部状态。
- 管理假设、证据缺口和调查队列。
- 决定调用哪个专项Skill和查询能力。
- 决定跨文件、跨时间、跨主机扩展。
- 控制停止条件。
- 汇总最终报告。

不负责：

- 自己解析所有日志格式。
- 自己实现ELF分析器。
- 自己查询底层数据库。
- 自己执行未知文件。

输入：

```json
{
  "case_id": "case-001",
  "file_details": {},
  "process_chain_hashes": [],
  "abnormal_events": [],
  "available_capabilities": [],
  "authorization_scope": {}
}
```

输出：

```json
{
  "case_id": "case-001",
  "verdict": {},
  "behavior_paths": [],
  "candidate_attack_paths": [],
  "scenario_assessments": [],
  "evidence_graph": {},
  "counter_evidence": [],
  "missing_evidence": [],
  "data_quality": {},
  "investigation_trace": []
}
```

### 8.2 静态Skill：`analyze-unknown-file-clues`

职责：

- 消费CDE和现有静态分析结果。
- 按ELF或脚本类型读取必要信息。
- 提取可用于下一步查询的线索。
- 分析包归属、签名和合法来源。
- 输出能力线索和限制，不重复做最终恶意判断。

内部可适配：

- 公司脚本解析Skill。
- `analyzing-linux-elf-malware`。
- HOFS样本读取能力。

输出：

```json
{
  "file_identity": {},
  "capability_leads": [],
  "iocs": [],
  "referenced_paths": [],
  "suggested_queries": [],
  "benign_indicators": [],
  "limitations": []
}
```

### 8.3 终端Skill：`analyze-linux-endpoint-behavior`

职责：

- 分析进程执行和父子关系。
- 分析文件运行时活动。
- 分析认证、用户和权限。
- 分析服务、配置和持久化。
- 分析容器运行时和宿主关系。
- 识别批量文件操作、敏感读取和系统破坏。

内部可以将Linux持久化作为参考或子能力，不必把每种持久化做成单独主Skill。

输出：

```json
{
  "execution_assessment": {},
  "process_chains": [],
  "file_behaviors": [],
  "auth_and_user_behaviors": [],
  "persistence_behaviors": [],
  "ransomware_behavior_metrics": [],
  "sensitive_access_behaviors": [],
  "candidate_graph_edges": [],
  "missing_evidence": []
}
```

### 8.4 网络Skill：`analyze-network-transport-behavior`

职责：

- 将连接尽可能归因到进程实体。
- 分析反向连接、监听和周期回连。
- 分析DNS、HTTP/TLS、代理和隧道。
- 分析出站流量和数据外传候选。
- 发现相同IOC在历史和其他主机的出现。

输出：

```json
{
  "process_connections": [],
  "c2_candidates": [],
  "exfiltration_candidates": [],
  "cross_host_matches": [],
  "candidate_graph_edges": [],
  "attribution_limitations": []
}
```

### 8.5 重建与研判Skill：`reconstruct-unknown-file-attack-path`

职责：

- 合并三层分析结果。
- 构建统一时间线和事件图。
- 评估后门、数据窃取和勒索场景。
- 生成行为路径和候选攻击路径。
- 映射TTP。
- 生成Verdict、反证和缺失证据。

输出：

```json
{
  "timeline": [],
  "graph": {
    "nodes": [],
    "edges": []
  },
  "behavior_paths": [],
  "candidate_attack_paths": [],
  "scenario_assessments": [],
  "ttp_mappings": [],
  "verdict": {},
  "counter_evidence": [],
  "missing_evidence": []
}
```

### 8.6 离线质量Skill

`audit-detection-bypass-coverage`继续保留，但不进入单案件运行链。

用途：

- 审计规则和采集覆盖。
- 识别字段链断裂。
- 识别三个场景的检测盲点。
- 帮助改进采集和测试。

## 9. Skill之间如何调用

```text
investigate-unknown-file-threat
│
├── analyze-unknown-file-clues
│     └── 返回静态线索和下一步查询建议
│
├── analyze-linux-endpoint-behavior
│     └── 返回执行、文件、用户、持久化和破坏行为
│
├── analyze-network-transport-behavior
│     └── 返回C2、外传和跨主机关联
│
└── reconstruct-unknown-file-attack-path
      └── 返回时间线、图、路径、三场景和Verdict
```

主Skill可以多次调用专项Skill：

```text
第一次终端分析：当前主机、初始窗口
第二次终端分析：扩展到更早时间
第三次终端分析：扩展到关联主机
```

专项Skill不能自行无限扩大范围；它应返回建议，由主Skill决定是否扩展。

## 10. 一个Skill具体应该怎么写

以主Skill为例。

### 10.1 推荐目录

```text
investigate-unknown-file-threat/
├── SKILL.md
├── agents/
│   └── openai.yaml
├── references/
│   ├── case-state.md
│   ├── investigation-workflow.md
│   ├── evidence-prioritization.md
│   ├── backdoor-investigation.md
│   ├── data-exfiltration-investigation.md
│   ├── ransomware-investigation.md
│   ├── stopping-conditions.md
│   └── output-contract.md
└── scripts/
    ├── validate_case.py
    ├── merge_skill_results.py
    ├── validate_evidence_graph.py
    └── validate_report.py
```

### 10.2 `SKILL.md`只写核心流程

推荐内容：

```markdown
---
name: investigate-unknown-file-threat
description: Investigate Linux unknown-file cases by orchestrating static,
endpoint, network, historical, and cross-host evidence. Use when an upstream
CDE or detection system reports an unknown file and the task is to reconstruct
its behavior or attack path and assess backdoor, data-exfiltration, or
ransomware activity.
---

# Investigate an unknown-file threat

1. Validate the case anchor and authorization scope.
2. Normalize existing table inputs before requesting more data.
3. Maintain facts, hypotheses, evidence gaps, coverage, and investigation queue.
4. Establish file identity and extract static investigation leads.
5. Prove or disprove execution before attributing downstream behavior.
6. Trace backward to provenance and forward to effects.
7. Expand across files, time, or hosts only when supported by evidence.
8. Evaluate backdoor, exfiltration, and ransomware hypotheses.
9. Build evidence-backed behavior and candidate attack paths.
10. Report counter-evidence, missing evidence, and data coverage.

Read the relevant scenario reference only when that scenario becomes plausible.
Never execute the unknown file on a normal host.
```

详细场景知识放在references中，避免`SKILL.md`过长。

### 10.3 references写什么

`backdoor-investigation.md`：

- 后门需要回答的问题。
- 可能的数据源。
- 支持证据。
- 合法反例。
- 什么情况下只能“可能”。

`data-exfiltration-investigation.md`：

- 敏感读取、归集、暂存、外传四阶段。
- 如何证明外传。
- 正常备份和同步反例。

`ransomware-investigation.md`：

- 批量文件行为。
- 服务和备份破坏。
- 共享存储和多主机影响。
- 合法加密和迁移反例。

### 10.4 scripts写什么

只放确定性、重复和容易出错的逻辑：

- 输入Schema验证。
- 结果合并。
- 证据ID引用完整性。
- 图节点和边校验。
- 输出报告Schema校验。

不要把“什么是后门”写成大量Python if-else规则。

## 11. 事件图如何建立

### 11.1 节点

- File
- Process
- User
- Session
- Host
- Container/Pod/Image
- IP/Domain/URL
- Service/Task
- Configuration
- Archive
- Alert
- Evidence

### 11.2 边

- `created`
- `wrote`
- `read`
- `renamed`
- `deleted`
- `executed`
- `spawned`
- `connected_to`
- `listened_on`
- `authenticated_to`
- `downloaded`
- `uploaded`
- `persisted_via`
- `triggered`
- `contained_in`
- `mounted_from`
- `correlated_with`

### 11.3 每条边必须包含

```json
{
  "edge_id": "EDGE-001",
  "source": "process:p1",
  "relation": "executed",
  "target": "file:f1",
  "time": "2026-07-28T10:21:03+08:00",
  "evidence_ids": ["E-PROC-001"],
  "status": "observed",
  "confidence": "high",
  "alternatives": []
}
```

### 11.4 关系强度

强关系：

- 同一稳定进程实体的直接事件。
- audit事件直接记录主体和对象。
- 文件Hash和rename链一致。
- 网络连接有进程归属。

中关系：

- 主机、用户、路径和短时间窗口共同匹配。
- 多个独立来源互相印证。

弱关系：

- 只有时间接近。
- 只有PID。
- 只有常见文件名、IP或命令。

弱关系不能成为确认攻击链的关键边。

## 12. 如何从事件图得到攻击链

### 12.1 锚点

锚点节点是目标未知文件：

```text
file:/tmp/.cache/update#sha256=abc
```

### 12.2 反向遍历

寻找：

```text
谁创建文件
← 谁启动创建进程
← 对应哪个会话
← 会话来自哪个入口
```

形成：

```text
外部请求
→ Web服务
→ Shell
→ 文件落地
```

### 12.3 正向遍历

寻找：

```text
文件被谁执行
→ 产生什么进程
→ 读写什么文件
→ 建立什么连接
→ 修改什么配置
→ 影响什么主机
```

### 12.4 路径筛选

优先保留：

- 与锚点文件直接相关。
- 时间顺序合理。
- 关系边有证据。
- 能解释三个场景中的关键行为。
- 不依赖过多推断。

剔除：

- 仅时间接近但没有实体关系。
- 与锚点无关的并行告警。
- 重复事件。
- 来源不可靠且无交叉验证的关系。

### 12.5 路径类型

#### 已观察行为路径

只包含`observed`和高可信`correlated`边。

#### 候选攻击路径

允许少量`inferred`边，但必须：

- 标注推断。
- 说明推断理由。
- 列出缺失证据。

#### 备选合法路径

例如：

```text
发布平台
→ 部署脚本
→ 未知版本程序
→ 合法监控外联
```

## 13. 三场景如何形成结论

### 13.1 后门

高价值证据组合：

```text
执行证据
+ 命令执行/远程控制行为
+ C2/监听/回连
+ 持久化或重复控制
```

但不要求所有案件都同时具备四项。Agent需要解释缺失项对结论的影响。

### 13.2 数据窃取

强结论需要尽可能形成：

```text
敏感数据访问
→ 数据归集/导出/压缩
→ 传输主体关联
→ 异常出站传输
```

只有读取、只有压缩或只有外联都不能单独确认窃取。

### 13.3 勒索

强结论需要：

```text
目标进程执行
→ 大量文件实际改写/加密
+ 服务/备份/恢复破坏或勒索信
+ 影响范围证据
```

加密函数静态存在不能确认勒索已经实施。

## 14. Verdict如何得到

Verdict不建议简单累加分数。采用证据门和解释比较。

### 14.1 问题顺序

1. 是否确认目标文件身份。
2. 是否确认执行。
3. 是否确认执行后行为。
4. 行为是否支持一个或多个攻击场景。
5. 是否存在合理合法解释。
6. 关键关系是否有独立证据。
7. 数据覆盖是否足以支持否定结论。

### 14.2 建议结果

- `confirmed_attack`
- `likely_attack`
- `suspicious_unconfirmed`
- `likely_benign`
- `insufficient_evidence`

### 14.3 示例

```json
{
  "result": "confirmed_attack",
  "confidence": 0.91,
  "severity": "high",
  "supported_scenarios": ["backdoor", "data_exfiltration"],
  "reasons": [
    {
      "statement": "未知文件被Web服务子进程执行",
      "evidence_ids": ["E-PROC-001", "E-WEB-002"]
    },
    {
      "statement": "目标进程建立外部C2并写入systemd持久化",
      "evidence_ids": ["E-NET-003", "E-FILE-004"]
    }
  ],
  "counter_evidence": [],
  "missing_evidence": [
    "未获得外传内容，仅根据数据归集和传输规模确认高可能外传"
  ]
}
```

## 15. 完整示例：从三张表到攻击链

### 15.1 初始输入

`T_FILE_DETAILS`：

```text
主机：web-01
文件：/tmp/.cache/update
类型：ELF
发现时间：10:23
DETAIL：php-fpm → sh → update
```

`T_PROCESS_CHAIN_HASH`：

```text
update：Grey
sh：White
php-fpm：White
```

异常事件：

```text
10:24 web-01连接198.51.100.20:443
```

### 15.2 初始分析

事实：

- 存在未知ELF。
- 上游提供php-fpm到目标的候选进程链。
- 存在时间接近的外部连接。

不能确定：

- `DETAIL`能否证明执行。
- 外部连接是否由目标进程产生。
- 文件如何落地。

假设：

- H1：Web入口下载后门。
- H2：合法Web发布任务。

### 15.3 证明执行

终端Skill查询进程事件：

```text
10:21:03 sh执行/tmp/.cache/update
process_entity_id=P-UPDATE
```

结论：

- 文件执行已确认。

### 15.4 追溯来源

查询文件事件：

```text
10:20:58 sh通过curl写入/tmp/.cache/update
```

查询父进程：

```text
php-fpm → sh → curl
```

查询Web日志：

```text
10:20:55 外部IP请求/upload/shell.php
```

查询`shell.php`：

```text
文件在10:18由Web请求上传，包含命令执行入口
```

形成反向路径：

```text
外部Web请求
→ shell.php
→ php-fpm
→ sh/curl
→ update落地
```

### 15.5 追踪后续行为

网络Skill：

```text
P-UPDATE连接198.51.100.20:443
每60秒重复
```

终端Skill：

```text
P-UPDATE写入/etc/systemd/system/update.service
systemctl enable --now update.service
```

后门场景：

- 执行：确认。
- C2：确认。
- 周期回连：确认。
- 持久化：确认。

### 15.6 跨时间

历史查询：

```text
昨天同一主机的/tmp/.x/helper连接相同C2
```

进一步发现：

```text
helper读取/root/.ssh/id_rsa
```

### 15.7 跨主机

认证查询：

```text
web-01使用root密钥登录db-01
```

db-01终端行为：

```text
导出数据库
→ 创建/tmp/db.tar.gz
```

网络行为：

```text
归档进程后的上传进程向同一C2发送大流量
```

数据窃取场景得到支持。

### 15.8 最终证据图路径

```text
外部IP
→ 请求shell.php
→ php-fpm执行Shell
→ curl下载未知ELF
→ 未知ELF执行
→ 建立C2
→ 写入systemd持久化
→ 访问SSH私钥
→ 登录db-01
→ 导出并归档数据库
→ 向C2外传
```

勒索场景：

- 未观察到批量文件修改。
- 文件事件覆盖完整。
- 当前案件不支持勒索，但后续需要持续监控。

### 15.9 最终输出

```text
Verdict：confirmed_attack
场景：后门 + 数据窃取
行为路径：已确认
攻击入口：WebShell
跨时间：发现昨日关联文件
跨主机：web-01 → db-01
关键缺失：无法查看HTTPS内容，但归集、进程归属和发送规模形成强外传证据
```

## 16. 当前设计仍需确认

1. 最终是否采用“一主四专”Skill结构。
2. 三张表的真实字段、顺序和语义。
3. Agent可调用的实际数据能力。
4. 运行时证据保留期。
5. 跨主机查询授权范围。
6. 事件图由现有平台保存还是由案件服务保存。
7. 主Skill和重建Skill是否合并。
8. 三场景评估是否独立Skill化，还是作为重建Skill的references。
9. 最终报告Schema。
10. 用于验证方案的三个真实或模拟案件。

## 17. 推荐结论

内部方案建议采用：

```text
一个主调查Skill
+ 静态、终端、网络三个专项Skill
+ 一个路径重建与研判Skill
+ 一个案件状态和证据图
+ 一个证据驱动的自主调查循环
```

其中：

- 大模型负责调查推理和下一步选择。
- 专项Skill提供领域分析工作流。
- 查询工具提供原始证据。
- 确定性代码负责解析、关联和校验。
- 攻击链从证据图中产生，而不是由大模型直接编写故事。

## 18. 关键工具及实现逻辑

### 18.1 工具设计原则

工具不是攻击判断规则，而是 Agent 的“眼睛”和“计算器”。

```text
Agent：
决定为什么查、查什么、查多大范围、如何解释。

查询工具：
从授权数据源读取真实数据。

确定性分析工具：
解析、规范化、关联、聚合、建图和校验。
```

所有查询工具必须：

- 只读。
- 参数化，不接受任意 Shell。
- 限制主机、路径、时间和返回条数。
- 返回原始记录引用。
- 返回数据覆盖、截断和丢失情况。
- 记录查询 ID、调用原因和参数。
- 支持分页，避免一次性加载海量数据。
- 将日志内容作为不可信数据，不能作为 Agent 指令。

### 18.2 统一工具返回结构

```json
{
  "query_id": "Q-001",
  "tool_name": "query_process_events",
  "query_scope": {
    "host_ids": ["web-01"],
    "start": "2026-07-28T10:08:00+08:00",
    "end": "2026-07-28T10:53:00+08:00"
  },
  "items": [],
  "coverage": {
    "status": "complete",
    "coverage_start": "...",
    "coverage_end": "...",
    "event_loss": 0,
    "truncated": false
  },
  "raw_references": [],
  "warnings": [],
  "next_cursor": null
}
```

## 19. P0证据查询工具

### 19.1 `load_initial_case`

#### 作用

读取现有三张表或等价 JSON，建立调查起点。

#### 输入

```json
{
  "case_id": "case-001",
  "file_record_id": "T_FILE_DETAILS:123",
  "include_process_hashes": true,
  "include_abnormal_events": true
}
```

#### 实现逻辑

1. 读取 `T_FILE_DETAILS`。
2. 解析文件、主机、用户和容器字段。
3. 解析 `DETAIL.context[]` 和 `tree[]`。
4. 根据确认后的顺序重建初始进程链。
5. 使用 PID、进程名和启动时间关联 `T_PROCESS_CHAIN_HASH`。
6. 加载相关异常事件。
7. 统一时间单位和时区。
8. 为每条原始记录分配证据 ID。
9. 返回缺失字段和解析警告。

#### 输出

- 初始文件锚点。
- 初始进程链。
- Hash信誉。
- 异常事件。
- 数据质量。

### 19.2 `get_file_analysis`

#### 作用

获取 CDE、HOFS、ELF或脚本分析结果，提取后续调查线索。

#### 输入

```json
{
  "sha256": "abc",
  "file_path": "/tmp/.cache/update",
  "sample_reference": "hofs://...",
  "requested_views": ["identity", "elf_structure", "strings", "script_behavior"]
}
```

#### 实现逻辑

1. 优先读取现有 CDE 结构化结果。
2. 确认真实文件类型。
3. 根据类型路由 ELF 或脚本分析适配器。
4. 提取路径、命令、IP、域名、URL和文件引用。
5. 提取可能的网络、持久化、归档、加密和敏感访问能力。
6. 为每条线索保存偏移、函数、行号或原始引用。
7. 查询软件包、签名和合法来源。
8. 只输出调查线索，不直接声称现场行为发生。

#### 输出

- 文件身份。
- 静态能力线索。
- IOC。
- 关联文件。
- 推荐查询。
- 合法来源线索。
- 分析限制。

### 19.3 `query_process_events`

#### 作用

证明文件是否执行，并重建父子进程和命令。

#### 输入

```json
{
  "host_ids": ["web-01"],
  "start": "...",
  "end": "...",
  "filters": {
    "file_path": "/tmp/.cache/update",
    "sha256": "abc",
    "pid": null,
    "process_entity_id": null
  },
  "include_ancestors": true,
  "include_descendants": true
}
```

#### 实现逻辑

1. 按路径、Hash或进程实体查询执行事件。
2. 使用 `host_id + boot_id + pid + process_start_time` 生成稳定进程实体。
3. 关联父进程实体，而不是只看 PPID。
4. 合并 auditd `SYSCALL/EXECVE/PATH/CWD/PROCTITLE`。
5. 规范化命令行、工作目录、UID/EUID和容器身份。
6. 构建祖先和子进程链。
7. 检查执行记录、文件Hash和路径是否一致。
8. 标记 PID 重用、链断裂和时间矛盾。

#### 输出

- `execution_observed/execution_unknown/not_observed`。
- 稳定进程实体。
- 父子进程链。
- 命令、用户、会话。
- 候选图边。

### 19.4 `query_file_events`

#### 作用

分析文件来源、运行时读写、释放文件、敏感访问和勒索行为。

#### 输入

```json
{
  "host_ids": ["web-01"],
  "start": "...",
  "end": "...",
  "filters": {
    "paths": ["/tmp/.cache/update"],
    "process_entity_ids": ["P-UPDATE"],
    "operations": ["create", "read", "write", "rename", "chmod", "delete", "execute"]
  }
}
```

#### 实现逻辑

1. 查询目标路径和目标进程的文件事件。
2. 统一 create/read/write/rename/chmod/chown/delete/execute 语义。
3. 使用 inode/device、Hash和rename前后路径连接文件实体。
4. 识别创建者、修改者和执行者。
5. 对新生成脚本、ELF、压缩包、配置和勒索信创建关联节点。
6. 保留大小、权限、Hash和路径变化。
7. 对高频事件按进程和时间窗口聚合，同时保留代表性原始记录。
8. 标记没有采集 read 事件等覆盖限制。

#### 输出

- 文件来源。
- 文件操作序列。
- 关联文件。
- 敏感访问候选。
- 勒索批量行为候选。
- 候选图边。

### 19.5 `aggregate_file_behavior`

#### 作用

将海量文件事件聚合为可供勒索和数据归集分析的行为指标。

#### 输入

```json
{
  "host_id": "web-01",
  "process_entity_id": "P-UPDATE",
  "start": "...",
  "end": "...",
  "bucket_seconds": 60
}
```

#### 实现逻辑

按进程和时间桶统计：

```text
读取文件数
写入文件数
重命名文件数
删除文件数
受影响目录数
读写字节数
操作速率
扩展名前后变化
文件大小/Hash/熵变化抽样
```

必须：

- 同时返回原始事件样本。
- 不直接输出“这是勒索”。
- 与该主机正常备份、发布和批处理基线比较。

#### 输出

- 文件行为时间序列。
- 异常批量行为候选。
- 影响目录。
- 代表性证据。
- 基线差异。

### 19.6 `query_network_events`

#### 作用

分析 C2、反向连接、监听、DNS、数据外传和跨主机通信。

#### 输入

```json
{
  "host_ids": ["web-01"],
  "start": "...",
  "end": "...",
  "filters": {
    "process_entity_ids": ["P-UPDATE"],
    "ips": [],
    "domains": [],
    "direction": "any"
  },
  "include_dns": true,
  "include_flow": true
}
```

#### 实现逻辑

1. 优先查询带进程实体的连接。
2. 合并 connect/listen/accept/close 和 DNS。
3. 连接主机、容器和网络namespace。
4. 计算方向、持续时间和收发字节。
5. 按进程、IP、域名和时间聚合周期行为。
6. 识别连接是否紧随文件执行、数据归集或压缩。
7. 将主机侧连接与DNS、代理、防火墙和NetFlow交叉验证。
8. 没有进程归属时标记 `not_attributable`。

#### 输出

- 进程连接。
- 监听端口。
- 周期回连候选。
- 外传候选。
- 跨主机通信。
- 归因限制。

### 19.7 `query_auth_and_session_events`

#### 作用

追溯登录入口、权限切换、凭据滥用和跨主机访问。

#### 实现逻辑

1. 查询 SSH、PAM、sudo、su 和TTY会话。
2. 关联账号、UID、来源IP、认证方式和目标主机。
3. 将会话与进程实体连接。
4. 查询账号、组、sudoers和SSH key变化。
5. 识别凭据文件访问后的后续登录。
6. 查询历史首次出现、异常时间和失败后成功。
7. 保留合法堡垒机和运维记录作为反证。

#### 输出

- 登录会话链。
- 权限切换。
- 账号/密钥变化。
- 跨主机认证候选。
- 合法运维上下文。

### 19.8 `query_persistence_and_service_events`

#### 作用

分析后门持久化和勒索对服务、备份、恢复能力的破坏。

#### 实现逻辑

查询并比较：

- cron、at。
- systemd service/timer。
- SysV、`rc.local`。
- Shell profile。
- SSH `authorized_keys`。
- `/etc/ld.so.preload`。
- 用户、sudoers和SUID/capability。
- 内核模块和udev。
- 容器启动配置。
- 数据库、备份、安全和业务服务启停。
- LVM、Btrfs、ZFS和备份快照。

对每个发现区分：

```text
配置存在
配置发生变化
配置指向未知文件
配置实际触发未知文件
```

#### 输出

- 持久化发现。
- 服务破坏。
- 备份/快照破坏。
- 实际触发证据。
- 基线和合法变更。

### 19.9 `query_container_context`

#### 作用

将容器内文件和进程映射到Pod、镜像、宿主主机和挂载。

#### 实现逻辑

1. 查询 container ID、Pod UID、namespace和image digest。
2. 映射容器PID与宿主PID。
3. 区分文件来自镜像、挂载卷还是运行时写入。
4. 查询容器启动命令、环境、capability和挂载。
5. 查询 container exec 和Kubernetes审计。
6. 查询相同镜像或Pod模板的其他实例。

#### 输出

- 容器身份。
- 宿主进程映射。
- 文件来源层。
- 挂载和共享卷。
- 同镜像跨主机实例。

### 19.10 `search_history_and_peers`

#### 作用

完成跨时间和跨主机检索。

#### 输入

```json
{
  "time_range": {
    "start": "...",
    "end": "..."
  },
  "scope": {
    "host_ids": [],
    "asset_groups": ["linux-production"]
  },
  "indicators": {
    "hashes": ["abc"],
    "paths": ["/tmp/.cache/update"],
    "commands": [],
    "ips": ["198.51.100.20"],
    "domains": [],
    "users": []
  }
}
```

#### 实现逻辑

1. 对Hash、路径、命令、账号、C2、持久化和勒索模式建立查询。
2. 返回匹配发生的主机和时间。
3. 标明匹配维度和强度。
4. 对常见IP、文件名和命令降低匹配强度。
5. 将历史事件返回为证据引用，而不是只返回计数。
6. 不自动认定所有匹配属于同一攻击。

#### 输出

- 历史重复事件。
- 同行主机匹配。
- 匹配强度。
- 跨时间/主机扩展建议。

### 19.11 `get_evidence_coverage`

#### 作用

判断“没有查到”是否可信。

#### 实现逻辑

对指定主机、数据源和时间范围返回：

- 是否启用采集。
- 覆盖开始和结束。
- 丢失事件。
- 延迟。
- 截断。
- 保留期。
- 查询限制。

#### 输出

```text
complete
partial
not_collected
not_available
unknown
```

## 20. P0确定性处理工具

### 20.1 `normalize_evidence`

将不同来源记录映射为统一证据模型。

关键逻辑：

- 时间规范化。
- 主机和容器身份规范化。
- 操作类型规范化。
- 原始值保留。
- 证据ID生成。
- 不在规范化阶段做恶意判断。

### 20.2 `resolve_entities`

识别同一个进程、文件、用户、主机和网络对象。

关键逻辑：

```text
Process = host + boot + pid + start_time
File = host/container + path/inode + hash + time
Host = stable asset ID / machine ID
Container = container ID / pod UID / image digest
```

返回：

- 确认合并。
- 候选合并。
- 冲突。
- 无法解析。

### 20.3 `merge_audit_records`

将同一 audit 事件中的：

```text
SYSCALL
EXECVE
PATH
CWD
PROCTITLE
SOCKADDR
```

按事件serial合并为一个结构化动作。

### 20.4 `build_evidence_graph`

#### 实现逻辑

1. 将已解析实体创建为节点。
2. 将直接事件创建为 `observed` 边。
3. 将稳定实体连接产生 `correlated` 边。
4. 只允许有证据ID的边进入正式图。
5. 推断关系进入候选层，不能伪装成直接事实。
6. 去除重复节点和重复边。
7. 检查时间方向和实体冲突。

### 20.5 `extract_candidate_paths`

#### 实现逻辑

1. 以未知文件为锚点。
2. 反向遍历创建、下载、会话和入口。
3. 正向遍历执行、子进程、文件、网络、持久化和影响。
4. 按证据强度、时间合理性和场景相关性排序。
5. 输出观察路径和候选路径。
6. 对路径断点生成缺失证据。
7. 同时生成合法替代路径。

### 20.6 `validate_investigation_report`

校验：

- 所有事实是否引用证据。
- 图边证据ID是否存在。
- Verdict原因是否有证据。
- `not_observed`是否有完整覆盖。
- 推断是否明确标记。
- 是否把静态能力误写为现场行为。
- 是否把网络主机事件误归因到进程。

## 21. 最小工具集合

一期最少实现：

```text
load_initial_case
get_file_analysis
query_process_events
query_file_events
aggregate_file_behavior
query_network_events
query_auth_and_session_events
query_persistence_and_service_events
search_history_and_peers
get_evidence_coverage

normalize_evidence
resolve_entities
build_evidence_graph
extract_candidate_paths
validate_investigation_report
```

容器场景再增加：

```text
query_container_context
```

## 22. 工具调用示例

```text
1. load_initial_case
   得到未知ELF、主机、时间和候选进程链

2. get_file_analysis
   得到C2域名、systemd路径和加密能力线索

3. query_process_events
   确认文件执行并获得稳定进程实体

4. query_file_events
   发现curl创建文件，目标进程写入systemd

5. query_network_events
   确认目标进程连接C2并周期回连

6. query_persistence_and_service_events
   确认service指向目标文件并实际触发

7. search_history_and_peers
   发现昨天和其他主机出现相同C2

8. query_auth_and_session_events
   发现使用SSH密钥登录数据库主机

9. build_evidence_graph
   建立文件、进程、连接、账号和主机关系

10. extract_candidate_paths
    生成后门和数据窃取路径

11. validate_investigation_report
    检查所有结论和证据引用
```

