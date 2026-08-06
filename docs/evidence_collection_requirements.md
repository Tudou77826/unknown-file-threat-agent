# Linux 未知文件攻击路径还原：证据采集需求清单

## 1. 目的

本文用于与产品、终端 Agent、日志平台和容器平台确认：当用户只提供一个 Linux 未知文件路径及案件时间时，系统需要向分析 Agent 提供哪些文件、日志、状态快照和结构化字段，才能判断文件是否参与真实攻击并还原攻击路径。

目标交互：

```text
用户：
今天发生了一个攻击事件，未知文件路径是 /tmp/.x/kinsing，
请研判该文件是否参与真实攻击，并还原攻击路径。

系统：
根据明确授权和只读采集策略，围绕文件路径、Hash、主机、容器和
案件时间窗口收集证据，执行文件本体分析、主机痕迹分析、网络分析、
容器分析和案件重建，输出证据化攻击路径、反证、缺失证据和 Verdict。
```

## 2. 范围变化

此前方案主要消费上游整理好的 `case_bundle.json`。如果希望 Agent 根据文件路径主动查找证据，项目将增加“证据发现与只读采集”能力。

建议仍将采集与研判分为两个逻辑阶段：

```text
证据发现与只读采集
  -> 规范化案件材料
  -> 专项分析
  -> 多源关联
  -> 攻击路径与 Verdict
```

不要让核心研判逻辑直接散乱地执行任意 Shell 命令。应由受控 Collector 提供白名单式、可审计、可限制时间和数据量的只读接口。

## 3. 安全原则

1. 不运行未知 ELF 或脚本。
2. 不对未知 ELF 直接运行 `ldd`。
3. 不访问样本中提取出的 URL、IP 或域名。
4. 默认只读，不修改日志、配置、文件权限、账号、容器或服务状态。
5. 不自动隔离、删除或终止进程。
6. 不直接读取与案件无关的秘密内容。
7. `/etc/shadow`、私钥、环境变量和进程内存属于高敏数据，必须有单独授权和脱敏策略。
8. 采集命令、执行时间、操作者、返回码、输出 Hash 和截断状态必须审计。
9. 在线主机采集可能改变 atime 或产生系统日志，应记录采集副作用。
10. 离线镜像应只读挂载；不要在证据镜像中执行程序。

## 4. 用户最少需要提供什么

最低启动条件：

```text
unknown_file_path
host_id 或可定位主机的信息
incident_time 或发现时间
```

强烈建议同时提供：

```text
file_sha256
container_id/pod_id（如适用）
alert_id
discovery_source
timezone
```

如果只有文件路径而没有主机和时间，Agent 无法可靠限定证据范围。

## 5. 调查窗口

建议采用分层窗口，而不是一次查询全部历史：

| 窗口 | 默认范围 | 用途 |
| --- | --- | --- |
| 核心窗口 | 事件前 30 分钟至后 60 分钟 | 恢复创建、执行、网络和持久化直接关系 |
| 上下文窗口 | 事件前后 24 小时 | 查找初始访问、下载、重复执行和清理痕迹 |
| 历史复发窗口 | 过去 7 天或 30 天 | 查找相同 Hash、路径、用户、IP、命令和周期行为 |
| 基线窗口 | 过去 30–90 天 | 判断管理员登录、服务行为、文件和配置是否正常 |
| 首次出现窗口 | 从文件首次发现时间向前扩展 | 追溯文件来源和最早落盘 |

所有窗口应可配置。数据平台必须返回查询是否完整、是否被截断以及实际覆盖时间。

## 6. 产品统一返回要求

不论数据来自文件、命令、API、EDR、SIEM 或容器平台，每条记录至少应包含：

```text
source_system
source_record_id
record_type
observed_at
original_time
timezone
host_id
container_id/pod_id（如适用）
raw_reference
collection_time
collector_version
truncated
parse_status
```

涉及进程时尽量包含：

```text
process_entity_id
pid
ppid
process_start_time
executable
command_line
uid/euid/auid
session_id
executable_sha256
```

涉及文件时尽量包含：

```text
path
normalized_path
inode
device
sha256
size
mode
uid/gid
mtime/ctime/atime/btime
actor_process_entity_id
operation
```

涉及网络时尽量包含：

```text
process_entity_id
pid
socket_id
protocol
src_ip/src_port
dest_ip/dest_port
dns_name
connection_start/end
bytes_sent/received
```

## 7. P0：未知文件自身

这是所有案件必须获取的数据。

### 7.1 文件内容或安全样本引用

需要：

- 样本本体，或受控对象存储引用。
- SHA256，必要时 MD5/SHA1。
- 文件大小。
- 文件 Magic/MIME。
- 完整路径。
- inode 和设备号。
- 权限、所有者、组。
- mtime、ctime、atime、btime（文件系统支持时）。
- 符号链接目标。
- 扩展属性和 Linux capabilities。

作用：

- 唯一标识文件。
- 判断扩展名与内容是否一致。
- 关联进程、网络提取物和沙箱报告。
- 判断文件是否被重命名或替换。
- 进行 ELF 或脚本静态分析。

注意：

- 文件不存在时也应采集历史文件事件、目录元数据和告警中的 Hash。
- 读取文件可能更新 atime，取决于挂载选项；应记录采集行为。
- 样本内容属于不可信输入。

### 7.2 推荐只读元数据

逻辑上等价于：

```text
stat
file
sha256sum
readlink
getcap
getfattr
```

实际产品应通过受控 Collector 输出结构化数据，不要求核心 Agent 拼接任意命令。

## 8. P0：进程与执行证据

目标：

- 证明未知文件是否执行。
- 恢复父子进程链。
- 确定执行命令、用户、权限和会话。

### 8.1 auditd

关键文件和配置：

```text
/var/log/audit/audit.log
/var/log/audit/audit.log.*
/etc/audit/auditd.conf
/etc/audit/audit.rules
/etc/audit/rules.d/*.rules
```

重要记录类型：

```text
SYSCALL
EXECVE
PATH
CWD
PROCTITLE
USER_CMD
USER_LOGIN
USER_AUTH
CRED_ACQ
CRED_DISP
SERVICE_START
SERVICE_STOP
CONFIG_CHANGE
DAEMON_START
DAEMON_END
```

作用：

- `EXECVE`：证明程序被执行及其参数。
- `SYSCALL`：提供 PID、PPID、UID、AUID、EUID、可执行路径、成功状态等。
- `PATH`：提供访问或操作的文件路径。
- `CWD`：提供执行时工作目录。
- `PROCTITLE`：补充完整命令行。
- `USER_CMD`：记录 sudo 等用户命令。

同一个 Audit Event 由一条或多条 Record 组成，必须按 Audit Event ID 聚合，不能把 `SYSCALL`、`EXECVE`、`PATH` 分别当成独立行为。[ausearch 官方手册](https://man7.org/linux/man-pages/man8/ausearch.8.html)

必须同时采集 Audit 配置和健康信息，因为：

- 没有相关 Audit Rule 时，“未发现 exec”不能证明没有执行。
- backlog、磁盘不足或审计进程异常可能导致丢失。
- 日志轮转可能造成案件窗口缺失。

产品应额外返回：

```text
audit_enabled
rules_loaded
backlog_limit
lost_records
audit_log_path
covered_time_range
rotated_files_included
```

### 8.2 systemd journal / journald

`systemd` 是服务和系统管理框架，`journald` 是其结构化日志系统。不要把 `systemd` 和 `syslog` 混为同一个文件。

典型存储位置：

```text
/var/log/journal/    持久日志（启用持久存储时）
/run/log/journal/    易失日志，重启后可能丢失
```

不建议自行解析二进制 `.journal` 文件。优先通过 `journalctl` 或产品侧 journal API 导出 JSON/JSON-SEQ。

关键字段：

```text
__REALTIME_TIMESTAMP
_BOOT_ID
_MACHINE_ID
_HOSTNAME
_PID
_UID
_GID
_COMM
_EXE
_CMDLINE
_SYSTEMD_UNIT
_SYSTEMD_USER_UNIT
_SYSTEMD_CGROUP
SYSLOG_IDENTIFIER
PRIORITY
MESSAGE
```

作用：

- 按 `_EXE`、`_PID`、Unit、Boot ID 和时间查询。
- 查看 systemd 服务启动、停止和失败。
- 查看 cron、sshd、sudo、内核和容器运行时日志。
- 区分不同系统启动周期。
- 验证某个 systemd Unit 是否实际启动目标文件。

`journalctl` 支持按 `_SYSTEMD_UNIT`、`_PID` 和可执行文件过滤，并可选择输出字段。[systemd 官方 journalctl 文档](https://www.freedesktop.org/software/systemd/man/255/journalctl.html)

产品应返回：

```text
journal_storage=persistent|volatile|none
boot_ids
covered_time_range
vacuum/rotation information
exported_fields
query_expression
```

### 8.3 传统 syslog 文件

不同发行版可能存在：

```text
/var/log/syslog
/var/log/messages
/var/log/daemon.log
/var/log/kern.log
/var/log/debug
```

作用：

- 补充服务、守护进程、内核和应用事件。
- 在没有完整 journald 导出时提供文本日志。
- 查询进程崩溃、服务重启、网络和内核异常。

局限：

- 文件位置和内容随发行版、rsyslog/syslog-ng 配置变化。
- 可能与 journald 重复。
- 必须识别重复来源，不能把同一日志转发副本当作独立证据。

建议同时采集：

```text
/etc/rsyslog.conf
/etc/rsyslog.d/*
/etc/syslog-ng/*
```

用于确认日志路由、远程转发和文件位置。

### 8.4 `/proc` 在线进程状态

仅对仍在运行的进程有效：

```text
/proc/<pid>/exe
/proc/<pid>/cmdline
/proc/<pid>/cwd
/proc/<pid>/status
/proc/<pid>/stat
/proc/<pid>/environ
/proc/<pid>/maps
/proc/<pid>/fd/
/proc/<pid>/mountinfo
/proc/<pid>/cgroup
/proc/<pid>/ns/
```

作用：

- 确认可执行路径、命令行、工作目录和身份。
- 查看进程打开的文件、Socket 和动态库。
- 确认 cgroup、容器和命名空间。
- 关联内存映射和已删除但仍在运行的程序。

敏感性：

- `environ` 可能包含凭据。
- `fd` 可能指向敏感文件和 Socket。
- `maps` 可能暴露库和内存布局。
- 必须按目标 PID 白名单采集并脱敏。

局限：

- `/proc` 不是历史日志。
- 进程退出后大部分信息消失。
- PID 会复用，必须记录采集时间和进程启动时间。

### 8.5 进程记账

如果启用了 process accounting：

```text
/var/account/pacct
/var/log/account/pacct
```

作用：

- 提供历史命令执行的补充记录。
- 在进程已退出且 auditd 不完整时提供线索。

局限：

- 默认可能未启用。
- 参数信息通常有限。
- 不能替代完整 Audit/EDR 进程事件。

## 9. P0：文件活动证据

目标：

- 追溯文件如何落盘。
- 确定创建、修改、赋权、重命名和删除者。
- 发现执行后生成的文件和配置变化。

### 9.1 必要事件

产品应尽量提供：

```text
create
write
rename
chmod
chown
unlink
execute
open/read（敏感文件场景）
```

每条事件应带：

```text
actor_process_entity_id
pid
process_start_time
path_before/path_after
inode/device
sha256（可得时）
operation
success
observed_at
```

### 9.2 文件系统快照和目录

围绕目标路径采集：

- 目标文件元数据。
- 父目录及相邻可疑文件的元数据。
- 同创建时间附近的文件。
- 同所有者、相似命名和相同 Hash 文件。
- 删除但仍被进程打开的文件引用。

重点目录：

```text
/tmp
/var/tmp
/dev/shm
/run
/run/user/*
/var/www
/srv
/opt
/usr/local/bin
/usr/local/sbin
用户 home
容器可写层
```

不要因为文件位于这些目录就直接判定恶意。

### 9.3 文件完整性和基线

如产品已有 AIDE、FIM、EDR 或镜像基线，要求：

```text
first_seen
last_seen
baseline_status
previous_hash
current_hash
change_actor
change_time
```

这可以回答：

- 文件是否新出现。
- 系统文件是否被替换。
- 配置是否在案件期间被修改。

## 10. P0：认证与用户证据

目标：

- 追溯谁进入主机。
- 将登录会话关联到 Shell 和未知文件进程。
- 发现暴力破解、异常 sudo 和账号变化。

### 10.1 认证日志

常见位置：

```text
/var/log/auth.log       Debian/Ubuntu 常见
/var/log/secure         RHEL/CentOS/Rocky/Alma 常见
/var/log/btmp
/var/log/wtmp
/var/log/lastlog
/run/utmp
```

相关配置：

```text
/etc/ssh/sshd_config
/etc/ssh/sshd_config.d/*
/etc/pam.d/*
/etc/security/*
```

作用：

- SSH 成功/失败。
- 来源 IP、端口、用户和认证方式。
- sudo、su、PAM 认证。
- 登录、注销和会话。
- 暴力破解后成功。

`wtmp/btmp/lastlog` 是二进制记录，应通过兼容解析器读取，不应当作文本。

### 10.2 用户和组

文件：

```text
/etc/passwd
/etc/group
/etc/shadow
/etc/gshadow
/etc/subuid
/etc/subgid
```

作用：

- 识别新增账号、UID 0 账号和异常 Shell。
- 确认目标进程用户。
- 比较账号修改时间和案件时间。

安全要求：

- `/etc/shadow` 和 `/etc/gshadow` 高度敏感。
- 默认应由产品侧输出账号状态摘要，而不是把密码 Hash 交给通用 Agent。
- 不需要破解或展示密码 Hash。

### 10.3 sudo

配置：

```text
/etc/sudoers
/etc/sudoers.d/*
```

日志来源：

```text
auth.log/secure
journald
auditd USER_CMD
```

作用：

- 确认普通用户是否通过 sudo 执行未知文件。
- 识别案件时间附近的权限提升。
- 区分最初登录用户和有效 root 身份。

### 10.4 Shell History

常见：

```text
/root/.bash_history
/home/*/.bash_history
/root/.zsh_history
/home/*/.zsh_history
/root/.python_history
/home/*/.python_history
```

作用：

- 查找下载、chmod、执行、cron、systemctl、清理痕迹等命令。

局限：

- 可被关闭、清除或篡改。
- 非交互 Shell 不一定记录。
- Bash History 可能在会话结束时才写入。
- 默认可能没有时间戳。
- History 只能作为辅助证据。

## 11. P0：Linux 持久化证据

### 11.1 cron 和 at

文件和目录：

```text
/etc/crontab
/etc/cron.d/*
/etc/cron.hourly/*
/etc/cron.daily/*
/etc/cron.weekly/*
/etc/cron.monthly/*
/var/spool/cron/*
/var/spool/cron/crontabs/*
/var/spool/at/*
```

日志：

```text
journald 中 cron/crond
/var/log/cron
/var/log/syslog
```

作用：

- 发现定时任务。
- 判断命令是否指向目标文件。
- 结合 cron 日志和进程事件确认实际触发。

### 11.2 systemd

系统级 Unit：

```text
/etc/systemd/system/*
/run/systemd/system/*
/usr/lib/systemd/system/*
/lib/systemd/system/*
```

用户级 Unit：

```text
/etc/systemd/user/*
/usr/lib/systemd/user/*
/home/*/.config/systemd/user/*
/root/.config/systemd/user/*
```

重点文件类型：

```text
*.service
*.timer
*.socket
*.path
*.target
```

重点字段：

```text
ExecStart
ExecStartPre
ExecStartPost
Environment
EnvironmentFile
User
Group
WorkingDirectory
Restart
WantedBy
Requires
After
```

需要同时获取：

```text
Unit 文件内容
Drop-in 配置
是否 enabled
当前/历史状态
journal 中启动记录
Unit 文件元数据和修改者
```

作用：

- 配置存在：仅 `artifact_detected`。
- `ExecStart` 指向未知文件：`target_linked`。
- journal/进程事件证明启动：`execution_confirmed`。

### 11.3 SysV 和 rc.local

```text
/etc/init.d/*
/etc/rc.local
/etc/rc*.d/*
/etc/inittab
```

作用：

- 检查传统启动脚本和运行级别持久化。

### 11.4 Shell 启动文件

```text
/etc/profile
/etc/profile.d/*
/etc/bash.bashrc
/etc/bashrc
/root/.bashrc
/root/.profile
/home/*/.bashrc
/home/*/.profile
/home/*/.zshrc
```

作用：

- 发现登录或启动 Shell 时执行的命令。
- 结合用户登录事件确认实际触发。

### 11.5 SSH 持久化

```text
/root/.ssh/authorized_keys
/home/*/.ssh/authorized_keys
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/sshd_config.d/*
```

作用：

- 查找新增 SSH Key、强制命令和异常选项。
- 结合基线、mtime、修改进程和后续登录验证。

存在 authorized_keys 是正常现象，不能直接判定后门。

### 11.6 动态链接器

```text
/etc/ld.so.preload
/etc/ld.so.conf
/etc/ld.so.conf.d/*
```

作用：

- 发现预加载共享库。
- 判断目标 `.so` 是否被系统级加载。
- 分析函数 Hook、隐藏进程或文件的可能性。

### 11.7 SUID、SGID 和 capabilities

需要产品输出扫描结果：

```text
SUID 文件
SGID 文件
file capabilities
owner/group
mode
sha256
package provenance
first_seen
```

作用：

- 发现异常提权入口。
- 判断未知文件是否被赋予特殊权限。

系统存在正常 SUID 文件，必须与软件包和基线比较。

### 11.8 udev、内核模块和启动配置

```text
/etc/udev/rules.d/*
/usr/lib/udev/rules.d/*
/etc/modules
/etc/modules-load.d/*
/etc/modprobe.d/*
/lib/modules/<kernel>/
/boot/
```

作用：

- 发现设备事件触发命令。
- 发现异常模块加载和启动配置。

此类证据权限和体量较高，可作为条件采集。

## 12. P0/P1：系统配置、软件包和合法来源

这些数据主要用于反证和判断文件来源。

### 12.1 软件包管理

Debian/Ubuntu：

```text
/var/lib/dpkg/status
/var/log/dpkg.log*
/var/log/apt/history.log*
/var/log/apt/term.log*
/etc/apt/
```

RPM 系：

```text
RPM 数据库（具体路径随发行版变化）
/var/log/dnf.log*
/var/log/yum.log*
/var/log/dnf.rpm.log*
/etc/yum.repos.d/*
/etc/dnf/
```

作用：

- 判断文件是否属于已安装软件包。
- 确认文件安装或升级时间。
- 验证 Hash、路径和发布来源。
- 识别案件是否处于正常升级窗口。

### 12.2 主机身份和时间

```text
/etc/os-release
/etc/hostname
/etc/machine-id
/proc/sys/kernel/hostname
/etc/timezone
/etc/localtime
/etc/chrony.conf
/etc/chrony/*
/etc/ntp.conf
/var/lib/systemd/timesync/
```

还需运行时摘要：

```text
当前 UTC/本地时间
时区
NTP/chrony 同步状态
Boot ID
启动时间
Kernel 版本
```

作用：

- 统一日志时区。
- 识别时钟漂移。
- 区分重启前后 PID 和 Journal。
- 解释多源时间冲突。

## 13. P0/P1：网络行为证据

### 13.1 主机实时网络状态

结构化等价数据：

```text
ss -plant/-uap
Socket inode
/proc/<pid>/fd 与 socket
/proc/net/tcp*
/proc/net/udp*
conntrack
```

作用：

- 将连接归属到目标进程。
- 获取源/目的地址、端口和协议。

局限：

- 只反映当前或短期状态。
- 进程退出后可能消失。
- 必须快速采集。

### 13.2 防火墙与主机网络配置

```text
nftables 规则和日志
iptables/ip6tables 规则和日志
ufw 配置和日志
firewalld 配置和日志
路由表
接口和地址
/etc/hosts
/etc/resolv.conf
```

常见日志：

```text
/var/log/ufw.log
/var/log/kern.log
journald/kernel
集中防火墙日志
```

作用：

- 确认连接是否允许、拒绝。
- 解释网络路径和本地地址。
- 发现规则被清空或修改。

### 13.3 网络遥测

优先级：

1. 带 Process Entity/PID 的 EDR 网络事件。
2. eBPF/Runtime Sensor 网络事件。
3. Zeek/NetFlow/防火墙/代理日志。
4. PCAP。

需要：

```text
DNS
HTTP
TLS
TCP/UDP Flow
开始/结束时间
字节数
进程归属
Host/Container
```

作用：

- 外联、下载、C2、Beacon、矿池、扫描和外传分析。

### 13.4 PCAP

若提供 PCAP，要求：

- 案件时间窗口。
- 采集点。
- 接口。
- 丢包率。
- 时间戳精度。
- BPF 过滤条件。
- 文件 Hash。
- 是否完整或截断。

PCAP 可用于：

- 详细协议分析。
- 提取下载文件。
- 对提取文件计算 Hash。
- 验证未知文件的网络来源。

## 14. P1：Web 服务器与应用日志

针对 PHP、JSP、ASP、HTML 或 Web 根目录未知文件。

### 14.1 Nginx

常见：

```text
/var/log/nginx/access.log*
/var/log/nginx/error.log*
/etc/nginx/nginx.conf
/etc/nginx/conf.d/*
/etc/nginx/sites-enabled/*
```

### 14.2 Apache/httpd

常见：

```text
/var/log/apache2/access.log*
/var/log/apache2/error.log*
/var/log/httpd/access_log*
/var/log/httpd/error_log*
/etc/apache2/*
/etc/httpd/*
```

### 14.3 Tomcat/Java Web

常见：

```text
$CATALINA_BASE/logs/*
应用容器日志
部署目录和 webapps
```

### 14.4 应用与反向代理

需要产品返回：

```text
request_id/trace_id
client_ip
forwarded_for
host
method
URI
status
user_agent
request_time
upstream
authenticated_user
application_instance
```

作用：

```text
外部HTTP请求
→ Web Server
→ PHP/JSP/HTML文件
→ 解释器/应用进程
→ 子进程或文件下载
```

注意反向代理环境中来源 IP 可能位于 `X-Forwarded-For`，必须结合可信代理配置，不能盲信请求头。

## 15. P1：容器环境证据

### 15.1 容器身份和配置

需要：

```text
container_id
pod_id
namespace
container_name
image_name
image_digest
created_at
started_at
entrypoint
command
environment（脱敏）
mounts/volumes
network namespace
pid namespace
user
privileged
capabilities
security profile
restart policy
```

作用：

- 区分宿主机和容器 PID。
- 判断文件来自镜像层、Volume 还是容器可写层。
- 判断容器是否具有高危权限。
- 关联容器重启和持久化。

### 15.2 Docker

应优先通过 Docker API/`inspect` 获取元数据，而不是让通用 Agent直接读取内部存储。

日志取决于 Logging Driver：

- `json-file`
- `local`
- `journald`
- `syslog`
- `fluentd`
- `splunk`
- 云日志等

Docker 默认可使用 `json-file`，但容器可以覆盖日志驱动；某些配置下 `docker logs` 不一定能看到有用内容。[Docker Logging Driver 文档](https://docs.docker.com/engine/logging/configure/) [Docker 容器日志文档](https://docs.docker.com/engine/logging/)

产品必须返回：

```text
logging_driver
log_source
covered_time_range
rotation/truncation
```

### 15.3 containerd/CRI/Kubernetes 日志

Kubernetes/CRI 常见：

```text
/var/log/pods/
/var/log/containers/
journald 中 kubelet 和容器运行时
```

Kubernetes 默认由 kubelet 管理容器日志，常见节点目录为 `/var/log/pods`；在 systemd 节点上 kubelet 和容器运行时通常写 journald。[Kubernetes 日志架构](https://kubernetes.io/docs/concepts/cluster-administration/logging/)

### 15.4 Kubernetes API 与审计

需要：

- Pod/Deployment/DaemonSet/StatefulSet/Job/CronJob YAML。
- Event。
- 容器状态和重启次数。
- Image Digest。
- ServiceAccount。
- Volume 和 Secret 引用元数据。
- `exec`、`attach`、`portforward` 等 Kubernetes Audit 事件。
- 创建、更新、patch、delete 的 API 操作者。

Kubernetes Audit 可以输出 JSON Lines 或 Webhook 事件，前提是集群配置了 Audit Policy 和 Backend。[Kubernetes Auditing 文档](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)

作用：

```text
谁通过kubectl exec进入Pod
谁修改Deployment
谁替换镜像
谁创建CronJob
未知文件属于镜像还是运行时写入
```

### 15.5 容器文件差异

需要：

- 镜像层文件清单。
- 容器可写层差异。
- Volume 内容和挂载来源。
- 目标文件是否存在于镜像。
- 首次出现时间和创建进程。

作用：

- 判断文件是否随镜像发布。
- 判断是否在容器运行后落盘。
- 判断删除容器是否会使文件消失。

## 16. P1：内核、崩溃和内存证据

条件触发：

- 怀疑 Rootkit。
- 进程隐藏。
- 文件已删除但进程仍运行。
- 注入或内存加载。
- 关键进程崩溃。

来源：

```text
journalctl -k / kernel log
/var/log/kern.log
coredumpctl / systemd-coredump 元数据
/var/lib/systemd/coredump/（配置相关）
内存镜像（经专门流程）
```

内存镜像和 Core Dump 高敏且体量大，应由专门取证流程处理，不属于默认采集。

## 17. 条件采集：动态沙箱

如果产品已有 Cuckoo、CAPE 或其他沙箱，要求提供：

```text
sample_sha256
task_id
provider/version
Linux镜像和架构
执行用户和参数
网络模式
开始/结束时间
超时状态
进程树
文件操作
网络连接
释放文件
行为签名
原始报告引用
```

沙箱结果用于证明样本能力，不自动证明真实主机发生相同行为。

## 18. 历史回溯查询

用户提出“今天发生后，过去同时间是否也发生”，建议产品支持以下历史查询：

### 18.1 相同文件

```text
相同 SHA256
相同路径
相同文件名
相同大小
相同父目录
```

### 18.2 相同执行方式

```text
相同 executable
相同 command line 规范形
相同父进程
相同用户
相同 systemd Unit/cron Entry
```

### 18.3 相同认证上下文

```text
相同来源 IP
相同用户
相同 SSH Key 指纹
相同 Session 类型
相同时间段
```

### 18.4 相同网络行为

```text
相同目的 IP/域名/端口
相同 DNS 查询
相同 TLS SNI/证书/指纹
相似 Beacon 周期
```

### 18.5 相同系统修改

```text
相同 cron 命令
相同 systemd Unit
相同 authorized_keys Key 指纹
相同 LD_PRELOAD 路径
```

历史结果必须带覆盖范围和保留策略。没有历史命中可能只是历史数据已过期。

## 19. Agent 调查工作流

### 阶段 1：限定案件

1. 解析未知文件路径、Host、Container 和事件时间。
2. 确定核心窗口和历史窗口。
3. 获取文件元数据和 Hash。
4. 确认目标是否仍存在、是否仍在运行。

### 阶段 2：文件本体

1. 类型识别。
2. ELF 或脚本静态分析。
3. 提取路径、命令、域名、IP 和持久化线索。
4. 不执行样本。

### 阶段 3：证明执行

优先查询：

1. EDR/Agent Process Entity。
2. auditd `EXECVE/SYSCALL/PATH`。
3. journald。
4. process accounting。
5. `/proc` 实时状态。

### 阶段 4：向前追溯

1. 父子进程。
2. 文件创建/下载/赋权。
3. SSH/Web/容器 `exec` 会话。
4. 登录来源和用户。
5. 历史相同执行。

### 阶段 5：向后扩展

1. 子进程。
2. 文件和配置修改。
3. 网络连接。
4. 账号和权限变化。
5. 持久化。
6. 清理和隐藏。

### 阶段 6：容器边界

1. Host/Container PID 映射。
2. 镜像与可写层。
3. Volume。
4. Kubernetes Audit。
5. 容器重启和启动配置。

### 阶段 7：历史回溯

1. 同 Hash。
2. 同路径/命令。
3. 同来源 IP/用户。
4. 同网络目标。
5. 同持久化配置。

### 阶段 8：案件重建

1. 多源实体关联。
2. 时间线。
3. 事件图。
4. 主攻击路径。
5. TTP。
6. 反证。
7. 缺失证据。
8. Verdict。

## 20. 不同数据能证明什么

| 数据 | 可以支持 | 不能单独证明 |
| --- | --- | --- |
| 文件 Hash/元数据 | 文件身份、位置、属性 | 已执行、恶意 |
| ELF Strings/Import | 潜在能力 | 真实行为 |
| auditd `EXECVE` | 真实执行和参数 | 文件一定恶意 |
| PID/PPID | 进程父子关系 | 攻击入口 |
| auth.log SSH 成功 | 登录事实 | 登录者就是攻击者 |
| Shell History | 操作线索 | 命令一定成功执行 |
| 网络 Flow + PID | 目标进程连接 | 一定是 C2 |
| 主机级 PCAP 无 PID | 主机通信事实 | 属于未知文件 |
| cron 内容指向目标 | 持久化配置关联 | 已实际触发 |
| cron 日志 + 进程事件 | 实际触发 | 初始配置者身份，除非另有证据 |
| systemd Unit | 启动配置 | 已 enabled/started |
| authorized_keys | Key 存在 | Key 为攻击者添加 |
| 沙箱行为 | 样本在沙箱中的能力 | 真实主机已发生相同行为 |
| ATT&CK 映射 | 行为分类 | 恶意结论或组织归因 |

## 21. 产品优先级清单

### P0：一期必须

1. 文件样本引用、Hash、路径和元数据。
2. Host ID、Container/Pod ID 和案件时间。
3. 进程启动、PID/PPID、启动时间、命令行、UID/EUID、可执行路径和 Hash。
4. 文件创建、写入、重命名、chmod、删除和执行事件。
5. SSH/PAM/sudo 认证事件和 Session。
6. 带 PID/Process Entity 的网络连接事件。
7. auditd 原始记录或已聚合事件，以及审计健康状态。
8. journald 导出及关键结构化字段。
9. cron、systemd、SSH key、profile、`LD_PRELOAD` 等配置内容和元数据。
10. cron/systemd 实际启动日志。
11. 日志覆盖时间、截断、轮转和丢失信息。
12. 历史按 Hash、路径、用户、IP 和命令查询能力。

### P1：强烈建议

1. 软件包来源和变更窗口。
2. Web Server/Application 日志。
3. DNS、HTTP、TLS、Zeek/NetFlow 和 PCAP 摘要。
4. Docker/Kubernetes 元数据、日志和 Audit。
5. 文件完整性基线。
6. Shell History。
7. SUID/SGID、Capabilities 和异常账号摘要。
8. 时间同步和 Boot ID。

### P2：条件增强

1. 完整 PCAP。
2. 沙箱动态报告。
3. 内存镜像和 Core Dump。
4. 深度 Rootkit/内核模块分析。
5. 企业级 UEBA 和长期认证基线。

## 22. 产品接口建议

不要只提供“读取任意文件”工具。建议提供受控接口：

```text
get_file_metadata(path, host_id, container_id)
get_sample_reference(path_or_hash)
query_process_events(host_id, container_id, time_range, path, hash, pid)
query_file_events(host_id, container_id, time_range, path, hash)
query_auth_events(host_id, time_range, user, source_ip, session_id)
query_network_events(host_id, container_id, time_range, process_entity_id, pid)
get_journal_events(host_id, boot_id, time_range, filters)
get_audit_events(host_id, time_range, path, pid, event_id)
get_persistence_artifacts(host_id, container_id, mechanisms)
get_container_context(container_id_or_pod_id)
search_history(indicator_type, value, time_range)
```

每个接口必须：

- 只读。
- 参数化，不拼接 Shell。
- 返回实际覆盖时间。
- 返回是否截断。
- 返回来源、记录 ID 和原始引用。
- 有最大记录数和分页。
- 有超时。
- 有权限审计。

## 23. 缺失证据语义

Agent 应区分：

```text
not_observed：
数据源覆盖完整，但没有观察到该行为。

not_collected：
对应数据源未采集。

not_available：
数据已轮转、丢失或无法访问。

not_attributable：
观察到事件，但无法归属于目标文件或进程。

conflicting：
不同来源给出冲突信息。
```

只有 `not_observed` 且数据源覆盖可靠时，才能作为“未发现行为”的有限反证。

## 24. 一期成功标准

产品提供 P0 数据后，Agent 应能：

1. 根据文件路径和案件时间自动制定只读调查计划。
2. 获取文件身份和静态分析结果。
3. 证明或否定文件是否执行。
4. 恢复父子进程、用户和登录会话。
5. 追溯文件创建、下载和权限变化。
6. 将网络连接归属到目标进程，或明确说明无法归属。
7. 判断持久化处于发现、目标关联还是实际触发层级。
8. 查询过去 7/30 天的相同 Hash、路径、命令、用户、IP 和配置。
9. 构建每条边都有证据引用的事件图。
10. 输出 TTP、反证、缺失证据和五级 Verdict。

