# Linux 未知文件攻击路径还原方法

## 1. 文档目的

本文定义本项目对“未知文件攻击路径还原”的统一方法，用于指导共享数据契约、专项 Skill、核心重建 Skill、测试样例和最终报告的设计。

本项目面向 Linux 主机与容器。当上游系统已经发现某个文件并将其判定为“未知文件”后，本项目接收上游提供的文件、进程、日志、认证、网络、持久化、静态分析和动态分析数据，围绕该文件回答：

1. 文件是什么，具有哪些静态特征或潜在能力。
2. 文件是否只是落盘，还是已经执行。
3. 谁在何时通过什么进程和命令执行了文件。
4. 文件执行前如何进入系统，执行后产生了哪些行为。
5. 文件是否建立了 Linux 持久化。
6. 多源事件之间能否形成有证据支持的因果链。
7. 已证明的行为可以映射到哪些 MITRE ATT&CK TTP。
8. 案件属于确认攻击、较可能攻击、可疑未确认、较可能正常，还是证据不足。

最终输出为：

```text
攻击路径 + 证据链 + TTP 映射 + 研判结论
```

## 2. 与通用攻击溯源的关系

通用攻击溯源通常包括证据采集、日志和流量分析、攻击者基础设施调查、攻击图构建、攻击复现以及事件报告。本项目采用其中的证据关联、时间线和攻击图思想，但对范围进行了约束。

| 通用攻击溯源工作 | 本项目中的处理方式 |
| --- | --- |
| 从网络设备、服务器和安全设备采集日志 | 默认由上游产品采集并通过 JSON 提供；Skill 不直接连接设备或数据库 |
| 获取进程、网络连接和文件系统状态 | 接收上游进程事件、网络事件、文件事件、磁盘快照或解析结果 |
| 分析完整 PCAP | 可接收 PCAP 摘要或结构化网络事件；完整 PCAP 分析是可选增强 |
| IP、域名和基础设施溯源 | 一期只把 IP、域名作为案件实体和 IOC，不进行攻击者真实身份或组织归因 |
| 漏洞利用分析 | 仅在上游提供相关证据时纳入路径；一期不负责漏洞验证和利用复现 |
| 使用攻击工具模拟攻击 | 不属于默认流程；未知文件不得在非隔离环境执行，也不使用 Metasploit 重放真实攻击 |
| 构建攻击图 | 构建以未知文件为中心、节点和边均引用证据的事件图 |
| 输出事件报告 | 输出结构化 `investigation_result.json` 和可读调查摘要 |

因此，本项目中的“溯源”主要表示：

```text
围绕未知文件追溯其来源、执行者、父子进程、相关用户、
网络行为、系统修改和持久化关系
```

它不表示仅凭 IP、域名或工具特征确定现实世界中的攻击者身份。

## 3. 核心原则

### 3.1 未知不等于恶意

上游将文件判定为未知，只表示当前检测系统无法将其可靠归类为黑或白。未知状态本身不能支持攻击结论。

### 3.2 事实、关联、推断和结论分离

输出必须区分四个层次：

| 层次 | 示例 |
| --- | --- |
| 原始事实 | auditd 记录 PID 5332 执行 `/tmp/.x/kinsing` |
| 关联结果 | PID 5332 属于某个 SSH 登录会话 |
| 分析推断 | 该执行可能与外部 SSH 登录有关 |
| 最终结论 | 多源证据支持该案件为较可能攻击 |

### 3.3 时间接近不等于因果关系

关系证据优先级为：

1. PID/PPID、`execve`、文件创建者、Socket 归属等直接关系。
2. Hash、完整路径、配置目标和稳定实体 ID。
3. 用户、会话、主机和容器关系。
4. 时间窗口关联。

仅有时间接近时，只能建立低置信度候选关系。

### 3.4 多个字段不等于多个独立来源

同一条原始告警中的路径、用户、进程和风险标签，不能被视为四份独立证据。证据独立性应依据 `source_system`、`source_record_id` 和采集方式判断。

### 3.5 保留反证和缺失证据

调查必须同时保存：

- 合法管理员操作。
- 受信软件包或内部发布版本。
- 业务变更窗口。
- 正常父进程和预期命令行。
- 公司合法网络目的地。
- 缺失的进程、网络、认证或持久化证据。

## 4. 总体处理流程

```text
上游案件 JSON
  -> 输入校验与标准化
  -> 数据质量评估
  -> 文件类型识别与静态分析
  -> 进程、文件、认证和网络事件解析
  -> Linux 持久化分析
  -> 多源实体关联
  -> 统一时间线
  -> 事件图与攻击路径
  -> TTP 映射
  -> 反证、证据门和最终研判
```

## 5. 第一阶段：接收和标准化案件数据

### 5.1 统一输入

上游数据应映射为：

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

### 5.2 标准化操作

- 将字段别名映射为统一名称。
- 将枚举值转为规范枚举，同时保留原始值。
- 将时间转为 ISO 8601 UTC，同时保留原始时间、单位和时区。
- 识别 Host、Container、User、Session、Process、File 和 Network Endpoint 实体。
- 记录每个标准字段对应的来源记录和原始字段。
- 对旧表结构使用独立适配器，不在后续分析逻辑中散布字段兼容代码。

## 6. 第二阶段：数据质量评估

数据质量决定后续能够建立多强的关系、能够输出多强的结论。

至少评估：

| 维度 | 主要问题 |
| --- | --- |
| 完整性 | 关键字段是否缺失 |
| 有效性 | Hash、IP、端口、PID、时间和路径是否合法 |
| 一致性 | 父子进程时间、文件生命周期和多源字段是否冲突 |
| 唯一性 | 是否存在重复上报和重复事件 |
| 时间质量 | 单位、时区、精度、时钟偏移和时间窗口是否可靠 |
| 可关联性 | 是否有 Host、Container、Hash、PID、启动时间、Session 或 Socket |
| 来源可靠性 | 数据是原始日志、上游推断还是转换结果，是否发生丢失或截断 |
| 覆盖性 | 是否具备回答执行、网络、认证和持久化问题的数据源 |

数据质量不能只输出一个总分。应同时输出：

- 各维度状态。
- 阻塞问题。
- 降级问题。
- 当前能够建立哪些关系。
- 当前不能支持哪些结论。

例如，网络事件只有目的 IP 和时间、没有 PID 或 Socket 时，可以保留网络线索，但不能高置信度归属于未知文件进程。

## 7. 第三阶段：未知文件本体分析

### 7.1 文件类型路由

类型识别优先级为：

```text
文件 Magic > Shebang > 内容语法 > MIME > 扩展名 > 上游 fileType
```

一期文件范围包括：

- ELF。
- Shell：`sh`。
- Python：`py`、`pyc`。
- PHP：`php`、`phtml`、`php3`、`php4`、`php5`、`php7`、`phps`、`php-s`、`pht`。
- JSP/Java Web：`jsp`、`jspa`、`jspx`、`jspf`、`jsw`、`jsv`、`jhtml`。
- ASP：`asp`。
- Web/HTML：`html`。

ASP、JSP 和 HTML 只分析其在 Linux 主机或容器中的文件及关联行为，不扩展到 Windows 专属取证。

### 7.2 ELF

安全的基础静态分析包括：

- Hash。
- ELF Header。
- 架构、位数和端序。
- Section、Segment 和熵。
- Symbol、Import 和动态链接。
- Strings 和 IOC。
- 打包或压缩特征。

静态信息表示潜在能力，不表示行为已经在真实主机发生。

### 7.3 脚本

默认只进行静态和安全解析：

- 识别语言、解释器和入口。
- 解析 AST、Token 或字节码。
- 提取命令、下载、文件、网络、权限和持久化行为。
- 记录代码位置和原始片段。
- 限制解码层数、输出大小和递归深度。
- 不使用 `eval`、`exec`、`source` 或其他方式直接运行未知脚本。

## 8. 第四阶段：证明文件是否执行

执行证据强度大致为：

| 证据 | 强度 |
| --- | --- |
| auditd/EDR 的直接 `execve` 或进程启动事件 | 高 |
| 可靠沙箱观察到样本启动 | 高，但只证明沙箱行为 |
| 上游明确且可靠的实时进程启动标记 | 中至高，取决于字段定义 |
| 文件访问时间变化 | 低 |
| 文件具有可执行权限 | 不能证明已执行 |
| 文件存在于 `/tmp` | 不能证明已执行 |

如果只能证明文件落盘，必须输出 `execution_unconfirmed`。

## 9. 第五阶段：向执行前追溯

以目标文件或目标进程为起点，向前查找：

1. 谁创建或下载文件。
2. 谁修改权限或重命名文件。
3. 哪个父进程执行文件。
4. 父进程属于哪个用户和登录会话。
5. 会话通过 SSH、Web 服务、容器 `exec` 或其他入口建立。
6. 来源 IP、用户和认证结果是否异常。

示例：

```text
外部 IP
  -> SSH 登录会话
  -> sshd
  -> bash
  -> curl 下载未知文件
  -> chmod 增加执行权限
  -> bash 执行未知文件
```

每个箭头必须绑定证据 ID。

## 10. 第六阶段：向执行后扩展行为

查找目标进程及其子进程在生命周期内产生的：

- 子进程。
- 文件创建、修改、删除和权限变化。
- DNS、HTTP、TLS、TCP 或 UDP 连接。
- 账号、sudo、SSH key 和系统配置修改。
- cron、systemd、`LD_PRELOAD` 等持久化行为。
- 日志删除、进程隐藏或其他防御规避行为。

网络事件必须优先通过 Process Entity、PID、Socket 或沙箱进程树归属。只有主机和时间相同，不足以证明连接属于未知文件。

## 11. 第七阶段：Linux 持久化分析

一期至少覆盖：

- cron/crontab。
- systemd service/timer。
- SysV init 和 `rc.local`。
- shell profile。
- SSH `authorized_keys`。
- `LD_PRELOAD`。
- 可疑用户、sudo 和启动脚本。
- SUID/SGID。
- udev、内核模块和容器启动配置。

持久化结论分三级：

```text
artifact_detected
  -> target_linked
  -> execution_confirmed
```

发现配置不等于配置指向未知文件，配置指向未知文件也不等于已经实际触发。

## 12. 第八阶段：统一时间线

所有事件统一时间后形成调查视图：

```text
10:00:00 SSH 登录
10:00:33 bash 启动
10:00:40 curl 下载文件
10:00:42 chmod 增加执行权限
10:00:44 未知文件执行
10:00:46 连接外部地址
10:00:51 cron 文件创建
10:01:00 cron 再次启动未知文件
```

时间线负责排序和确定调查窗口；事件图负责表达关系。二者不能混用。

## 13. 第九阶段：事件图和攻击路径

### 13.1 节点

- Host。
- Container。
- User。
- Session。
- Process。
- File。
- Network Endpoint。
- Persistence Artifact。
- Alert。

### 13.2 边

- `parent_of`
- `executed`
- `created`
- `modified`
- `downloaded`
- `connected_to`
- `authenticated_as`
- `persisted_by`
- `triggered`

每条边至少包含：

```json
{
  "edge_id": "edge-001",
  "source_node_id": "process-bash-5332",
  "target_node_id": "file-sha256-...",
  "relationship": "executed",
  "evidence_ids": ["ev-audit-execve-001"],
  "confidence": "high",
  "relationship_basis": "direct_exec_event"
}
```

核心 Skill 从完整事件图中提取与目标文件连通且满足证据门的子图，形成最终攻击路径。孤立事件和弱时间关联可以保留在调查结果中，但不应强行加入主攻击路径。

## 14. 第十阶段：TTP 映射

TTP 映射只消费已经由证据支持的行为：

```text
证据事实
  -> 标准行为
  -> ATT&CK tactic/technique/sub-technique
```

每个映射必须包含：

- tactic。
- technique ID 和名称。
- evidence IDs。
- 映射理由。
- 置信度。

TTP 不能单独证明恶意，也不能用于攻击组织归因。

## 15. 第十一阶段：反证和最终研判

### 15.1 结论枚举

- `confirmed_attack`
- `likely_attack`
- `suspicious_unconfirmed`
- `likely_benign`
- `insufficient_evidence`

### 15.2 关键证据门

`confirmed_attack` 至少要求：

```text
已证明未知文件执行
+ 已证明恶意行为、C2、持久化或破坏效果
+ 至少一个独立来源佐证，或可靠沙箱直接观察
```

`likely_attack` 表示攻击链大部分闭合，但仍缺一个关键环节。

`suspicious_unconfirmed` 表示存在风险信号，但执行、因果关系或恶意效果不足。

`likely_benign` 需要明确合法来源、预期行为和可验证反证。

`insufficient_evidence` 表示当前数据不能支持方向性判断。

### 15.3 置信度与严重性

- 置信度表示结论有多可靠。
- 严重性表示如果结论为真，潜在影响有多大。
- 数据质量会限制最高置信度，但不直接等价于攻击概率。

## 16. 不采用攻击重放作为默认验证方法

通用方法可能建议使用攻击模拟工具重放攻击。本项目不将其作为默认步骤，原因包括：

- 目标是防御性案件研判，不是红队或渗透测试。
- 未知样本可能破坏系统或逃逸分析环境。
- 重放相似攻击只能验证“这种路径可能发生”，不能证明原案件确实如此发生。
- Metasploit 等工具产生的痕迹可能与真实攻击不同。

本项目使用以下验证方式：

1. Schema 和确定性解析器测试。
2. 单 Skill 正例、反例和缺字段测试。
3. 跨 Skill 场景测试。
4. 隔离沙箱动态分析。
5. 合成但不可执行的事件夹具。
6. 经明确授权的安全仿真结果作为外部输入。

## 17. 与五类正式 Skill 的对应

| 方法阶段 | 正式 Skill |
| --- | --- |
| 输入标准化、数据质量、实体和证据模型 | 各 Skill 共享资源；核心 Skill 负责案件入口 |
| ELF 基础分析、事件关联、事件图和最终研判 | `reconstruct-unknown-file-attack-path` |
| 脚本静态解析 | `analyze-unknown-scripts` |
| Linux 持久化 | `analyze-linux-persistence` |
| TTP 映射 | `map-evidence-to-mitre-attack` |
| 检测规则、字段链和传感器覆盖审计 | `audit-detection-bypass-coverage` |

攻击绕过 Skill 是离线检测能力质量保障，不参与每个案件的攻击路径判断。

## 18. 示例：未知 ELF 案件

已观察数据：

```text
外部 IP 成功登录 root
sshd -> bash -> /tmp/.x/kinsing
kinsing 连接外部矿池地址
/etc/cron.d/update 指向 /tmp/.x/kinsing
cron 后续再次启动 kinsing
```

事件图：

```text
network_endpoint:external-ip
  -> authenticated_to
session:ssh-root
  -> created
process:bash
  -> executed
file:kinsing
  -> connected_to
network_endpoint:mining-pool
file:kinsing
  -> persisted_by
artifact:/etc/cron.d/update
artifact:/etc/cron.d/update
  -> triggered
process:kinsing-2
```

如果每条边都有独立日志、配置或动态行为证据，可以形成高可信攻击路径。如果只有 `/tmp`、root 和 Shell 父进程，则最多属于可疑信号，不能确认攻击。

## 19. 最终报告结构

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
    "severity": "high",
    "reasons": [],
    "counter_evidence": []
  },
  "data_quality": {},
  "missing_evidence": [],
  "warnings": []
}
```

## 20. 安全边界

- 不在非隔离环境运行未知 ELF 或脚本。
- 不自动访问样本中的 URL、域名或 IP。
- 不把 IOC 命中、ATT&CK 标签或可疑路径单独作为攻击结论。
- 不执行攻击重放、漏洞利用或红队操作。
- 不进行攻击者组织或现实身份归因。
- 不直接修改、删除或隔离生产资产。
- 不因数据缺失编造证据。

## 21. 方法来源与改写说明

本文参考了 CSDN 文章《在网络安全领域，溯源并还原攻击路径是一项重要的工作》中关于证据收集、关联分析、攻击图和报告总结的通用方法，并结合本项目的 Linux-only、未知文件中心、JSON 输入、证据化事件图和 Skill 化交付要求进行了重新组织与工程化改写。

原文作者：CSDN 博主“阿贾克斯的黎明”  
原文链接：https://blog.csdn.net/m0_57836225/article/details/141615032  
原文许可：CC BY-SA 4.0
