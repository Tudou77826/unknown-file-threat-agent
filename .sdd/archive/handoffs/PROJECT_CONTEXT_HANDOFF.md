# Linux 未知文件攻击路径还原 Skill 项目上下文交接

> 更新时间：2026-07-20  
> 用途：用于开启新的 AI/Codex Session 时恢复完整项目上下文。  
> 当前阶段：需求和范围已基本明确，已有一个早期 Python MVP 和公司攻击绕过 Skill；五类正式 Skill 尚未完成。

> [!IMPORTANT]
> 本文件是 2026-07-20 的历史交接版本，其中“下一步编写五类 Skill”和“较完整案件 JSON 作为主要输入”等内容已被后续立项讨论修正。  
> 新 Session 必须优先读取 `PROJECT_COMPLETE_HANDOFF.md` 的“0. 本次 Session 最新结论”。  
> 当前阶段已经调整为：暂停正式 Skill 开发，先盘点现有三张表和运行时数据，明确终端系统层、网络传输层、静态与二进制结构层的采集诉求，并完成端到端方案与可行性确认。

## 1. 项目一句话定义

本项目只面向 Linux：在上游系统已经发现并判定某个文件为“未知文件”之后，接收上游提供的未知文件、告警、进程、主机日志、网络、持久化和动态行为等 JSON 数据，通过五类可独立使用的 Skill，还原该未知文件相关的攻击路径，组织可追溯证据链，并研判它是否属于真实攻击。

最终目标输出：

```text
攻击路径 + 证据链 + TTP 映射 + 研判结论
```

当前不要求搭建完整 Agent。现阶段的正式产出是五类可独立触发、可独立运行、可独立测试、以后能被总 Agent 编排的 Skill。

## 2. 项目背景

公司已有两套与未知文件检测有关的业务代码。

第一套代码负责向终端 Agent 下发扫描任务和防护策略，通过 Kafka 接收终端上报的恶意文件、未知文件和异常进程信息，并完成文件列表查询、统计、文件判定、撤销判定、文件下载、资产管理和数据生命周期维护。

第二套代码负责文件检测流程：接收 Kafka 检测消息、Kafka Hash 消息或 REST 主动检测请求，下载并解密文件，通过 JNI 调用 C++ CDE 引擎，递归解压压缩包，对文件执行数据库匹配、启发式分析、压缩层级统计和子文件类型收集，最后输出黑文件、白文件、压缩异常或未知文件，并完成上报、隔离和入库。

因此，本项目不需要重新实现以下能力：

- 文件扫描和发现。
- 黑文件、白文件、未知文件分类。
- CDE、JNI、C++ 检测引擎。
- Kafka 消费、文件下载、解密和解压。
- HOFS 文件存储。
- 数据库表查询和业务入库。
- 上游日志、流量和主机证据采集。

本项目从“文件已经被判定为未知”开始，解决检测系统之后的研判问题。

## 3. 已锁定的范围

### 3.1 操作系统范围

只实现 Linux，不实现 Windows。

一期主要文件对象包括：

- Linux ELF 二进制文件。
- Shell/Bash 脚本。
- Python 脚本。
- PHP 脚本。
- 在 Linux 环境中出现的其他脚本文件。

PowerShell 只有在 Linux PowerShell 场景中才属于一期范围；不实现 Windows Event Log、注册表、计划任务、WMI、Windows 服务和 Autoruns 等 Windows 专属攻击路径。

### 3.2 任务范围

需要回答：

1. 未知文件是什么，是否具有可疑静态特征、混淆或危险行为。
2. 文件是只落盘，还是已经执行。
3. 文件由谁、在什么时间、通过什么命令和进程链执行。
4. 文件执行后创建了什么进程、文件、网络连接和系统修改。
5. 是否存在 cron、systemd、SSH key、LD_PRELOAD 等 Linux 持久化。
6. 零散事件之间是否存在时间、进程、文件、用户、主机或容器关联。
7. 哪些行为能够映射到 MITRE ATT&CK TTP。
8. 能否形成有证据支撑的攻击链。
9. 该案件是真实攻击、较可能攻击、可疑但未确认、较可能正常，还是证据不足。

### 3.3 明确不做

- 不搭建完整生产 Agent。
- 不负责真实数据库连接。
- 不依赖某张表一定能够直接访问。
- 不负责威胁情报平台、API 安全、密码学、漏洞管理、红队或渗透测试。
- 不做攻击者组织归因。
- 不因为一个 IOC、一个 ATT&CK 标签或一个可疑路径就直接判定真实攻击。
- 不在非隔离环境执行未知 ELF 或脚本。
- 暂不实现业务割接、业务日志专项、业务影响分析。

## 4. 对“未知文件攻击路径还原”的统一理解

此前形成的概念可以保留：

```text
未知文件攻击路径还原
= 文件/脚本本体分析
+ 执行痕迹分析
+ 主机日志和系统证据
+ 动态行为
+ Linux 持久化
+ 多源事件关联
+ TTP 映射
+ 证据化研判
```

它不是简单判断文件是否恶意，而是围绕未知文件建立事件因果关系。

例如：

```text
外部 SSH 登录
  -> sshd 创建 bash
  -> bash 执行 /tmp/.x/kinsing
  -> kinsing 连接外部 IP
  -> cron 每分钟再次执行 kinsing
```

只有当每条关系都有日志、进程、配置、网络或动态分析证据引用时，它才是一条可信攻击路径。`cron` 是 Linux 定时任务机制；“定时拉起”表示 cron 按配置重复启动目标程序，因此可以成为持久化证据。

## 5. 五类正式 Skill

公司只会提供两个已有 Skill：攻击绕过类和脚本解析类。攻击绕过类已经拿到，脚本解析类尚未拿到。其余能力需要本项目自行实现或从 Anthropic 安全类 Skill 中筛选、改写。

### 5.1 攻击绕过类 Skill

建议正式名称：`audit-detection-bypass-coverage`

来源：公司已有 `attack-rule-auditor`。

职责：离线审计检测规则、采集器、Parser、Normalizer 和测试样例，识别检测覆盖盲点、字段链丢失、脆弱条件、未测试变体和传感器限制。

输入不是单个案件 JSON，而是：

- 检测规则目录或文件。
- Linux/容器场景。
- 采集器、Parser、Normalizer 代码或字段描述。
- 测试夹具。
- Runtime、Sensor、Kernel 等上下文。

输出包括：

- ATT&CK 覆盖缺口。
- 字段链缺口。
- 绕过变体矩阵。
- 测试缺口。
- 修复计划和防御性代码建议。

它属于质量保障模块，不直接判断某个未知文件是否为真实攻击。它生成的 `attack_path_matrix` 表示规则对场景攻击路径的覆盖，不表示主机上实际发生的案件攻击路径。

### 5.2 脚本解析类 Skill

建议正式名称：`analyze-unknown-scripts`

状态：公司 Skill 尚未提供，拿到后以接入和轻量改写为主，保留已有功能。

职责：分析 Linux 上的 Shell、Python、PHP 等未知脚本，提取可解释行为。

建议统一输出：

- 脚本语言、解释器和入口。
- 编码、压缩、混淆和解码层。
- 命令执行和子进程创建。
- 下载、解压和执行行为。
- 文件创建、删除、权限修改和隐藏路径。
- 网络地址、域名、URL、端口和其他 IOC。
- 持久化、凭据访问、发现、横向移动、C2 和影响行为。
- 每个结论对应的代码位置、原始片段或证据 ID。
- 置信度、限制和未解析部分。

默认只做静态和安全解析；需要运行时必须交给隔离沙箱。

### 5.3 Anthropic 安全类改写 Skill

建议正式名称：`reconstruct-unknown-file-attack-path`

这是五类中的核心 Skill，负责最终案件级证据关联、攻击路径重建和真实性研判。

可参考和改写的 Anthropic Skill 包括：

- `analyzing-linux-elf-malware`
- `analyzing-linux-audit-logs-for-intrusion`
- `analyzing-linux-system-artifacts`
- `analyzing-malware-behavior-with-cuckoo-sandbox`
- `analyzing-network-traffic-of-malware`
- `building-incident-timeline-with-timesketch`
- `triaging-security-incident`

核心职责：

- 标准化上游案件 JSON。
- 对 ELF 做基础静态研判，或接收上游静态分析结果。
- 还原父子进程链和执行命令。
- 关联文件创建、修改、访问和执行事件。
- 关联认证、用户、网络、异常事件和动态行为。
- 合并脚本解析、Linux 持久化和 TTP Skill 的结构化结果。
- 建立带证据引用的事件图。
- 输出攻击路径、证据链、反证、缺失证据和最终结论。

这是最终输出 `攻击路径 + 证据链 + 研判结论` 的主要 Skill。

### 5.4 TTP 类 Skill

建议正式名称：`map-evidence-to-mitre-attack`

职责：把已经得到证据支持的行为映射到 MITRE ATT&CK tactic、technique 和 sub-technique。

输出至少包括：

- `tactic`
- `technique_id`
- `technique_name`
- `evidence_ids`
- `confidence`
- `mapping_reason`

约束：

- TTP Skill 只做行为映射，不单独下恶意结论。
- 一个命令名或关键字不能自动证明某个 TTP。
- 不能因为 TTP 相似就进行攻击组织归因。
- 每个映射必须引用原始证据。

### 5.5 Linux 持久化类 Skill

建议正式名称：`analyze-linux-persistence`

参考来源：`analyzing-persistence-mechanisms-in-linux` 和 `analyzing-linux-system-artifacts`。

一期至少覆盖：

- cron/crontab。
- systemd service/timer。
- SysV init 和 `rc.local`。
- shell profile，例如 `.bashrc`、`.profile`。
- SSH `authorized_keys`。
- `LD_PRELOAD` 和动态链接器配置。
- 可疑用户、sudo 配置和启动脚本。
- SUID/SGID 异常文件。
- udev、内核模块和容器启动配置。

必须区分：

```text
发现持久化配置
  != 配置指向未知文件
  != 配置已经触发未知文件执行
```

三者证据强度不同。只有配置内容、目标文件、时间、用户及实际执行日志能够关联时，才能形成强持久化证据。

## 6. 五类 Skill 的关系

五类 Skill 不是五个等权、顺序固定的处理步骤。

```text
                           +-----------------------------+
                           | 攻击绕过类                  |
                           | 离线审计检测能力和盲点      |
                           +-----------------------------+

上游 case_bundle.json
  -> 脚本解析类（脚本案件）
  -> Linux 持久化类
  -> TTP 类
  -> Anthropic 改写核心类
  -> 攻击路径 + 证据链 + TTP + 研判结论
```

攻击绕过类主要服务于检测能力质量保障；其余四类参与案件运行时分析。核心重建 Skill 可以直接消费原始 JSON，也可以消费其他 Skill 的结构化结果。

## 7. 输入数据原则

mentor 已说明可以暂时不考虑数据来源，默认所需告警、未知文件、日志、磁盘快照、网络连接、PCAP 摘要、配置文件和动态分析结果能够由产品侧提供。

因此当前设计原则是：

- 表名仅作为字段来源说明。
- Skill 不查询数据库。
- 上游通过 JSON/API/消息向 Skill 提供数据。
- 数据缺失时不能编造，需要输出 `missing_evidence`。
- 所有输入必须保留来源、时间和原始引用，便于审计。

## 8. 已明确的上游字段

### 8.1 未知文件和进程字段

当前已知可由 `T_FILE_DETAILS` 或等价上游 JSON 提供：

| 字段 | 含义及用途 |
| --- | --- |
| `fileHash` | SHA256，未知文件主标识 |
| `md5` | 辅助文件标识 |
| `filePath` | 文件完整路径，用于关联进程、持久化和文件事件 |
| `fileType` | ELF、脚本、压缩包等类型 |
| `fileSize` | 文件大小 |
| `fileMode` | Linux 文件权限 |
| `Source` | 一级资产/网元 ID |
| `Sub_Asset` | 二级资产/节点 ID |
| `Status` | 0 白、1 黑、2 待检测、3 未知、4 非检测黑、5 可疑白 |
| `Sync_status` | 处理和同步状态，其中 5 表示带回溯进程链 |
| `Discovery_Time` | 首次发现时间 |
| `Recent_Time` | 最近发现时间 |
| `File_modify_time` | 文件修改时间 |
| `File_create_time` | 文件创建时间 |
| `File_access_time` | 文件访问时间 |
| `File_user/File_UID` | 文件所有者和 UID |
| `File_Group/File_GID` | 文件所属组和 GID |
| `Process_NAME` | 触发文件的进程名 |
| `PID/PPID` | 进程 ID 和父进程 ID |
| `UID/GID/EUID/EGID` | 进程真实及有效身份 |
| `PROCESS_CREATE_TIME` | 进程创建时间 |
| `HOFS_PATH` | 文件样本存储引用 |
| `TASK_ID/SCAN_TYPE` | 扫描任务和实时/任务扫描来源 |
| `DETAIL` | 进程链 JSON |
| `USER_NAME/VISITOR_IP/LOGIN_ACCOUNT` | 用户和访问上下文 |
| `POD_ID/CONTAINER_ID/CONTAINER_NAME` | 容器上下文 |
| `EXTEND_FILED` | 扩展信息，例如 CPU ID |
| `REALTIME_TYPE` | 0 文件落盘，1 进程启动 |
| `SPECIAL_STATUS` | 特征状态标记 |
| `hashlist` | 进程链关联文件 Hash 列表 |

### 8.2 DETAIL 进程链

已提供的结构近似：

```json
{
  "context": [
    {
      "pid": "1234",
      "euid": "0",
      "path": "/tmp/.x/kinsing",
      "processName": "kinsing",
      "cmdline": "/tmp/.x/kinsing",
      "processStarTime": 1776914444221,
      "tree": [
        {
          "pid": "5332",
          "path": "/usr/bin/bash",
          "processName": "bash",
          "cmdline": "-bash",
          "processUser": "root,zjl1|0",
          "processStarTime": 1776914233979
        },
        {
          "pid": "5330",
          "path": "/usr/sbin/sshd",
          "processName": "sshd",
          "cmdline": "/usr/sbin/sshd -D",
          "processUser": "root,root|0",
          "processStarTime": 1776914000000
        }
      ]
    }
  ],
  "feature": {
    "traceable": true
  }
}
```

当前 MVP 假设 `tree[]` 是由近到远的祖先进程，因此先反转，再追加目标进程：

```text
sshd -> bash -> kinsing
```

该顺序仍需与产品侧确认。

### 8.3 进程链 Hash 信誉

`T_PROCESS_CHAIN_HASH` 或等价 JSON 字段：

| 字段 | 含义 |
| --- | --- |
| `hash` | 进程链文件 Hash |
| `hashType` | Black、White、Suspecious/Suspicious、Grey 等信誉级别 |
| `pid` | 进程 PID |
| `processName` | 进程名 |

当前 MVP 使用 `pid + processName` 精确关联；只匹配 PID 时降低关联置信度。

### 8.4 异常事件字段

`T_abnormal_event_TO_REPORT_OS` 或等价上游 JSON 可提供：

| 字段 | 含义及用途 |
| --- | --- |
| `event_id` | 原始事件唯一标识 |
| `evidence` | 文件和进程上下文 JSON |
| `src_ip/dest_ip` | 源和目的 IP |
| `attacker_ip/onthreat_ip` | 攻击相关 IP |
| `src_port/dest_port` | 网络端口 |
| `occur_time/recent_time/detect_time/report_time` | 事件时间线 |
| `attack_phase` | 上游攻击阶段 |
| `attack_status` | 攻击状态 |
| `confidence` | 上游置信度，不能直接作为最终置信度 |
| `times/duration` | 事件次数和持续时间 |
| `detail` | 进程链和文件详情 JSON/文本 |
| `pod_id/host_id` | 容器和主机上下文 |
| `user_name/visitor_ip/login_account` | 用户和登录上下文 |
| `sundries` | 用户配置或引擎检测 JSON |

## 9. 建议的统一输入契约

后续应把各种来源映射为一个 `case_bundle.json`：

```json
{
  "schema_version": "1.0",
  "case_id": "case-001",
  "host": {},
  "unknown_file": {},
  "alert": {},
  "process_events": [],
  "file_events": [],
  "network_events": [],
  "auth_events": [],
  "log_events": [],
  "persistence_artifacts": [],
  "static_analysis": {},
  "dynamic_analysis": {},
  "attachments": []
}
```

每条证据至少需要：

```text
evidence_id
source
observed_at
host_id/container_id
raw_reference
reliability
```

时间必须统一时区和单位，同时保留原始时间值。

## 10. 建议的统一输出契约

每个专项 Skill 应返回统一结果信封：

```json
{
  "skill_name": "...",
  "skill_version": "...",
  "status": "success|partial|failed",
  "findings": [],
  "evidence": [],
  "missing_evidence": [],
  "warnings": [],
  "errors": []
}
```

核心重建 Skill 最终输出 `investigation_result.json`：

```json
{
  "case_id": "case-001",
  "attack_path": {
    "nodes": [],
    "edges": []
  },
  "evidence_chain": [],
  "ttp_mappings": [],
  "persistence_findings": [],
  "verdict": {
    "result": "likely_attack",
    "confidence": 0.82,
    "reasons": [],
    "counter_evidence": []
  },
  "missing_evidence": []
}
```

攻击路径边建议至少支持：

- `parent_of`
- `executed`
- `created`
- `modified`
- `downloaded`
- `connected_to`
- `authenticated_as`
- `persisted_by`
- `triggered`

每个节点和边都必须引用 `evidence_ids`，不能只给自然语言推测。

## 11. 研判标准

建议结论枚举：

- `confirmed_attack`
- `likely_attack`
- `suspicious_unconfirmed`
- `likely_benign`
- `insufficient_evidence`

研判原则：

- “未知”不是“恶意”。
- 临时目录、root 身份、Shell 父进程分别只是风险信号。
- 多个来自同一条原始告警的字段不能当作多份独立证据。
- 强结论需要执行事实和恶意效果，或多源独立证据互相印证。
- 必须保留反证，例如合法管理员操作、已知软件来源、业务变更窗口和正常父进程。
- 置信度表示结论可靠程度，严重性表示潜在影响，二者不能混用。
- 证据不足时必须输出缺少什么，不能强行二选一。

建议关键门：

```text
confirmed_attack:
  已证明未知文件执行
  + 已证明恶意行为、C2、持久化或破坏效果
  + 至少一个独立来源佐证，或可靠沙箱直接观察

likely_attack:
  攻击链大部分闭合
  + 存在多项强关联证据
  + 仍有一个关键环节未完全证明

suspicious_unconfirmed:
  有风险信号，但执行、因果关系或恶意效果不足

likely_benign:
  有明确合法来源、预期行为和可验证反证

insufficient_evidence:
  当前数据无法支持方向性判断
```

## 12. 现有公司攻击绕过 Skill 的详细分析

位置：

```text
unknown-file-threat-agent/
  attack-rule-auditor-master/
    attack-rule-auditor-master/
```

核心定位：Linux、Containers、Kubernetes 场景和 Network Devices 的防御性 MITRE ATT&CK 覆盖真实性审计器。

它的强项：

- 使用本地 ATT&CK 索引和场景模型建立覆盖分母。
- 不接受只有 ATT&CK 标签的覆盖声明。
- 检查行为、Data Component、规则条件和子技术绑定。
- 验证 Collector -> Parser -> Normalizer -> Rule -> Alert 字段链。
- 检查正例、反例、变体和字段链测试。
- 根据 Runtime、Sensor、Kernel、Kubernetes 审计质量限制覆盖结论。
- 输出绕过矩阵、覆盖缺口、修复计划和防御性补丁建议。
- 安全边界明确，不输出攻击 Payload 和可操作绕过步骤。

它与案件研判的差异：

- 输入是规则、代码和测试包，不是 `case_bundle.json`。
- 输出是检测能力是否可靠，不是案件真实性。
- `attack_path_matrix` 是检测场景覆盖矩阵，不是真实事件因果链。
- 它适合离线运行，不适合每个未知文件案件都执行完整数十阶段流水线。

已发现的接入问题：

1. 当前 Codex Skill 校验器报告 `SKILL.md` 顶层 `version` 字段不兼容；最终应根据公司目标 Agent 的 Skill 规范修正或包装。
2. `package_check.py` 和 `script_dependency_check.py` 默认向不存在的 `laji/attack_data/reports` 写报告，当前环境执行失败。
3. `evals/evals.json` 引用的部分 `laji/test_inputs` 未包含在当前包中。
4. 当前目录存在双层 `attack-rule-auditor-master`，接入时应使用稳定包装路径，但暂不直接改公司原包。
5. README 中的 `388/388` 表示本地模型和模板范围，不代表用户真实检测规则已经达到完整覆盖。

建议接入方式：

- 保留公司原始包，避免一开始大改内部算法。
- 在外层建立薄适配 Skill。
- 修正最终平台要求的 `SKILL.md` 元数据。
- 强制显式指定输出目录。
- 补充最小规则样例和 Smoke Test。
- 将主要结果适配为统一 `coverage_gap_report.json`。
- 不把该报告作为案件攻击路径证据，只作为检测盲点和证据完整性参考。

## 13. 当前代码状态

当前项目目录：

```text
D:\My Files\研一\huawei\Anthropic-Cybersecurity-Skills-main\unknown-file-threat-agent
```

已经存在一个早期 Python MVP：

- `run_agent.py`：读取三类示例 JSON，依次调用普通 Python 模块。
- `skills/normalizer.py`：标准化文件、主机、进程链和异常事件。
- `skills/process_chain_analyzer.py`：提取进程链、root、SSH、Shell、Downloader 等证据。
- `skills/abnormal_event_correlator.py`：把异常事件转换为证据。
- `skills/attack_path.py`：生成简单攻击步骤。
- `skills/verdict.py`：加分式初步研判。
- `examples/`：Kinsing 风格示例输入。
- `schemas/`：早期结构文件。
- `docs/`：字段映射、Skill 草案和 TODO。

已实现的 MVP 能力：

```text
读取 T_FILE_DETAILS-like JSON
  -> 解析 DETAIL.context 和 tree
  -> 关联 T_PROCESS_CHAIN_HASH
  -> 转换异常事件
  -> 生成简单 evidence
  -> 生成简单 attack_steps
  -> 生成规则加分 verdict
```

示例链：

```text
sshd -> bash -> /tmp/.x/kinsing
```

重要定位：这些 `skills/*.py` 只是普通 Python 模块和算法草稿，不是已经完成的标准 Skill。它们可以复用为未来正式 Skill 的 `scripts/`，但不能计入五类正式交付。

当前 `run_agent.py` 应冻结为测试 Harness，不继续扩展成完整 Agent。

## 14. 当前原型的已知问题

1. `verdict.py` 使用简单累加分数，重复弱证据可能被累计为 `confirmed_attack`。
2. 当前分数本身可能超过 100，只是 confidence 被截断到 0.99。
3. 没有证据去重和来源独立性判断。
4. 没有反证、合法解释和业务变更上下文。
5. 没有正式的关键证据门。
6. 攻击步骤主要按证据类型映射，尚未可靠按时间和因果关系排序。
7. 异常事件尚未严格按主机、容器、PID、文件 Hash 和时间窗口关联。
8. `case_context.schema.json` 当前实际上是示例对象，不是包含 `$schema`、`type`、`properties`、`required` 的正式 JSON Schema。
9. DETAIL 中 `tree[]` 顺序、时间单位和部分枚举尚未确认。
10. 尚未实现 ELF 静态分析、脚本解析、Linux 持久化和 TTP 映射。

## 15. 当前项目真正停留的位置

已经完成：

- 明确项目只做未知文件检测后的攻击路径还原。
- 明确只做 Linux。
- 明确上游以 JSON 提供所需数据，不直接依赖数据库。
- 明确最终输出为攻击路径、证据链、TTP 和研判结论。
- 明确一期需要五类 Skill。
- 已拿到并初步审计公司攻击绕过 Skill。
- 已建立一个能够跑通 Kinsing 示例的早期 Python MVP。
- 已梳理主要上游字段和 DETAIL 进程链含义。

尚未完成：

- 五类 Skill 的正式目录、`SKILL.md`、`agents/openai.yaml` 和自包含资源。
- 共享输入、证据、中间结果和最终结果 JSON Schema。
- 公司攻击绕过 Skill 的正式兼容包装。
- 公司脚本解析 Skill 接入，因为代码尚未拿到。
- Linux 持久化 Skill。
- TTP Skill。
- Anthropic 改写的核心攻击路径重建 Skill。
- 可靠研判模型和证据门。
- 单元测试、Skill Eval 和跨 Skill 场景测试。

因此不能把当前状态描述为“Agent 已经完成”或“五类 Skill 已经完成”。当前属于：

```text
需求收敛完成
+ 数据字段初步梳理完成
+ 原理验证 MVP 已跑通
+ 现有公司 Skill 初步审计完成
-> 即将进入正式 Skill 契约和实现阶段
```

## 16. 当前主要难点

### 16.1 数据关联而不是字段堆积

真正难点不是把字段放进 JSON，而是证明两个事件属于同一次活动。需要综合：

- Host/Container 是否一致。
- 文件 Hash 和路径是否一致。
- PID/PPID、进程启动时间是否一致。
- 用户和 EUID 是否一致。
- 时间窗口是否合理。
- 网络连接是否确实属于目标进程。
- 持久化配置是否确实指向该文件。

### 16.2 证据与推断分离

例如 `/tmp`、root、Shell、外部 IP 都是可疑信号，但不是单独的攻击证明。输出必须区分：

- 原始事实。
- 关联结果。
- 分析推断。
- 最终结论。

### 16.3 攻击路径的时间与因果顺序

时间相近不等于存在因果关系。需要优先使用 PID/PPID、文件创建者、网络 Socket 归属、配置目标等直接关系，再使用时间窗口补充。

### 16.4 多 Skill 契约一致性

脚本解析、持久化和 TTP Skill 必须统一 `evidence_id`、时间、实体标识和置信度，否则核心 Skill 无法可靠合并。

### 16.5 研判不能只做打分

正式方案需要关键门、证据独立性、反证和缺失证据。简单加分只能用于排序，不能单独决定 `confirmed_attack`。

### 16.6 公司 Skill 与最终运行平台兼容

Skill 的业务逻辑可复用，但 Codex、Claude 或公司内部 Agent 对 frontmatter、工具声明、安装目录和输出方式可能不同，需要轻量平台适配。

### 16.7 ELF 与脚本分析差异

脚本可以较直接地恢复命令和字符串；ELF 需要结合 Header、Section、Symbol、Import、Strings、打包特征和动态行为。核心 Skill 必须对文件类型路由，不能使用完全相同的分析流程。

## 17. 可执行实施计划

### 阶段 0：冻结范围和原型

- [x] 锁定 Linux-only。
- [x] 锁定不实现未知文件检测。
- [x] 锁定当前不搭完整 Agent。
- [x] 将现有 `run_agent.py` 定位为测试 Harness。
- [ ] 不再向旧 MVP 直接堆叠新业务逻辑。

### 阶段 1：定义共享数据契约，最高优先级

- [ ] 编写正式 `case_bundle.schema.json`。
- [ ] 编写 `evidence.schema.json`。
- [ ] 编写 `skill_result.schema.json`。
- [ ] 编写 `investigation_result.schema.json`。
- [ ] 统一时间格式、实体 ID、证据 ID 和来源字段。
- [ ] 定义必填、可选和缺失字段处理。
- [ ] 把现有 Kinsing 示例迁移为正式契约。
- [ ] 增加正常管理员操作和证据不足样例。

验收：所有样例通过 Schema；缺字段时得到明确错误或 `partial`，不崩溃、不编造。

### 阶段 2：正式接入攻击绕过 Skill

- [ ] 保留公司原包。
- [ ] 明确目标 Agent 的 Skill 元数据规范。
- [ ] 建立外层兼容 Skill。
- [ ] 修正/包装 `version` 等元数据问题。
- [ ] 显式配置输出目录，解除 `laji` 隐式依赖。
- [ ] 补齐最小规则和测试输入。
- [ ] 运行 Smoke Test 和内部校验。
- [ ] 输出统一 `coverage_gap_report.json`。
- [ ] 文档中声明其结果不能作为案件攻击路径。

验收：能独立审计一个 Linux 检测规则目录，给出字段链、覆盖和绕过缺口。

### 阶段 3：实现 Linux 持久化 Skill

- [ ] 创建标准 Skill 目录和 `SKILL.md`。
- [ ] 实现 cron 和 crontab 解析。
- [ ] 实现 systemd service/timer 解析。
- [ ] 实现 SSH key、shell profile 和 `rc.local`。
- [ ] 实现 LD_PRELOAD、SUID/SGID 和可疑启动项。
- [ ] 按路径、Hash、用户、时间和执行事件关联未知文件。
- [ ] 输出配置存在、目标关联、实际执行三个证据层级。
- [ ] 编写正例、反例、缺字段和合法配置测试。

验收：能够证明或否定“某个持久化项是否指向并实际启动未知文件”。

### 阶段 4：实现 TTP Skill

- [ ] 建立 Linux 相关行为到 ATT&CK 的受控映射。
- [ ] 支持 tactic、technique 和 sub-technique。
- [ ] 每个映射强制引用 `evidence_ids`。
- [ ] 增加映射理由和置信度。
- [ ] 处理一对多、多对一和证据不足情况。
- [ ] 禁止从 TTP 自动推导恶意结论或组织归因。

验收：相同行为证据得到稳定映射；没有行为证据时不输出伪 TTP。

### 阶段 5：接入公司脚本解析 Skill

- [ ] 等待公司代码。
- [ ] 审计其真实输入、输出、依赖和安全边界。
- [ ] 保留已有解析能力。
- [ ] 适配统一 `case_bundle` 和 `skill_result`。
- [ ] 增加 Linux Shell、Python 和 PHP 样例。
- [ ] 验证混淆、Downloader、命令执行和持久化行为提取。
- [ ] 确保默认不直接运行未知脚本。

验收：能够输出带代码位置或证据引用的 `script_behavior_report`。

### 阶段 6：实现核心攻击路径重建 Skill

- [ ] 筛选并改写相关 Anthropic Skill。
- [ ] 集成 ELF 基础静态分析或静态分析结果适配。
- [ ] 实现进程、文件、网络、认证、持久化和动态行为关联。
- [ ] 构建事件图节点和边。
- [ ] 按直接因果关系优先、时间窗口次优排序。
- [ ] 合并脚本、持久化和 TTP 结果。
- [ ] 实现证据去重和来源独立性。
- [ ] 实现反证和合法解释。
- [ ] 实现关键证据门和五级 verdict。
- [ ] 输出 `investigation_result.json` 和可读摘要。

验收：每条攻击路径边都能追溯到证据，结论包含理由、反证和缺失证据。

### 阶段 7：单 Skill 和组合测试

- [ ] 每个 Skill 运行确定性脚本测试。
- [ ] 使用通用 Agent 单独加载各 Skill 测试触发和工作流。
- [ ] 使用薄测试 Harness 串联中间 JSON。
- [ ] 不搭生产 Agent，只验证 Skill 组合可行性。
- [ ] 固化 Eval Prompt、预期结构和回归样例。

至少覆盖：

1. SSH -> Bash -> Kinsing -> 外联 -> cron 的真实攻击样例。
2. 管理员在 `/tmp` 运行合法维护脚本的反例。
3. 只有未知 ELF 落盘、没有执行证据的证据不足样例。
4. cron 指向未知文件但没有实际执行日志的部分证据样例。
5. 混淆脚本下载 ELF、执行并创建 systemd 服务的完整样例。
6. 容器内未知 ELF 的样例。
7. 时间冲突、PID 复用、字段缺失和来源矛盾样例。

## 18. Skill 是否可以在总 Agent 之前测试

可以，而且应该这样测试。

Skill 本质是可复用的专业工作流说明、参考数据和确定性脚本，不需要等完整 Agent 建好才运行。

测试层次：

1. 直接运行 Skill 的 Python 脚本，检查 JSON 和 Schema。
2. 让支持 Skill 的 Codex、Claude 或公司通用 Agent 单独加载一个 `SKILL.md`，处理测试案件。
3. 对不原生支持 Skill 的 Agent，把 `SKILL.md` 作为系统/任务说明，并把脚本和参考文件作为工具资源提供。
4. 使用临时薄 Harness 顺序调用多个 Skill，通过文件传递中间 JSON。

这类测试是 Skill 开发的一部分，不代表提前搭建生产 Agent。

## 19. 下一 Session 建议起点

新 Session 不应重新讨论是否搭完整 Agent，也不应继续扩展旧 `run_agent.py`。建议直接从“阶段 1：共享 JSON Schema”开始。

推荐给新 Session 的提示词：

```text
请先完整阅读 unknown-file-threat-agent/PROJECT_CONTEXT_HANDOFF.md。
本项目只做 Linux，当前不搭完整 Agent，正式产出是五类 Skill。
请从阶段 1 开始：设计并实现 case_bundle、evidence、skill_result 和
investigation_result 四个正式 JSON Schema，并把现有 Kinsing 示例迁移为
符合新契约的测试样例。不要修改公司 attack-rule-auditor 原始包，也不要
继续扩展 run_agent.py。完成后运行 Schema 校验并说明字段设计。
```

## 20. 后续仍需向 mentor/产品确认的问题

这些问题不阻止先设计 Schema，但会影响后续关联准确度：

- 最终 Skill 运行平台是 Codex、Claude、公司内部 Agent，还是需要多平台兼容。
- `DETAIL.context[].tree[]` 的正式顺序。
- 所有时间字段的单位、时区和时钟误差。
- PID 是否可能跨时间复用，以及是否有 process entity ID。
- `hashType` 的正式枚举和 `Suspecious` 拼写是否固定。
- 文件 Hash 字段是否始终为 SHA256。
- 网络事件能否提供 PID、Socket、容器和时间关联。
- 持久化配置是否提供文件内容、修改事件和实际触发日志。
- 动态分析结果的正式字段。
- 最终 verdict 枚举和置信度是否需要符合公司已有标准。
- Skill 的交付目录、打包格式、依赖限制和验收方式。

## 21. 最终成功标准

项目完成时，应有五个正式 Linux Skill，并满足：

- 每个 Skill 都有清晰触发条件、输入、输出和安全边界。
- 每个 Skill 能独立运行和独立测试。
- 所有 Skill 使用兼容的 JSON 和证据 ID 契约。
- 公司两个已有 Skill 的核心功能得到保留。
- 未知 ELF 和 Linux 脚本案件都能被正确路由。
- 最终攻击路径中的每条关系都能追溯到证据。
- TTP 不脱离证据映射。
- 持久化区分配置、关联和实际执行。
- 最终结论包含置信度、理由、反证和缺失证据。
- 没有完整证据时不会把“未知”误判成“确认攻击”。
- 五类 Skill 能被一个临时通用 Agent/Harness 组合验证，之后再进入生产 Agent 搭建阶段。
