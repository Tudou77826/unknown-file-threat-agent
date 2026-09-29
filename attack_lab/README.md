# Attack Lab — 步骤 02 靶场执行运行手册

桌面阶段（采集器、转换器、沉淀管线、16 个剧本）已用合成数据端到端验证。本手册是靶场阶段的执行步骤。

## 前置条件

| 项 | 要求 | 说明 |
|---|---|---|
| Linux 靶机 | x86_64，root，auditd + gcc + python3 + tar/curl | 需装态势感知系统探针（规则侧被测对象） |
| 内核头 | 可选，仅 t1547-006 需要 | 缺失时该剧本自动跳过 |
| 环境文件 | `/opt/secval-lab/approved_endpoints.txt` | CMDB 导出的批准端点（IP 列表，# 注释） |
| 授权 | 靶机仅用于演练，剧本载荷无害（唯一行为：本机回连一次性 TCP） | 数据不出授权环境 |

## 部署（一次性）

```bash
# 1. 采集规则
cp collector/audit-rules.conf /etc/audit/rules.d/secval.rules && augenrules --load
# 2. 剧本库与工作区
mkdir -p /opt/secval-lab/cases /opt/secval-lab/bundles
cp -r playbooks /opt/secval-lab/
```

## 逐 Case 执行

```bash
# 靶机上（每条恶意 + 良性剧本各一次）
/opt/secval-lab/collector/collect.sh <case-id> \
    bash /opt/secval-lab/playbooks/malicious/t1105-ingress-tool-transfer/run.sh

# 取回执行机
scp -r lab-vm-01:/opt/secval-lab/bundles/<case-id>.bundle bundles/

# 执行机上沉淀为标准 Case（Windows 下用 python，路径含中文时注意编码）
python attack_lab/settle_case.py \
    --source attack_lab/playbooks/malicious/t1105-ingress-tool-transfer \
    --bundle bundles/<case-id>.bundle --host-id lab-vm-01 --suite validation_cases
```

## 沉淀后（人工门槛，不可跳过）

1. 复核生成的 `case.json`：GT 双层依据、expected_rule/expected_ai、关键证据是否与遥测一致；
2. 复核 `replay/events/*.jsonl` 抽样（process/network/file/counter_evidence 四类是否齐全）；
3. 确认后 `python -c "from threat_agent.capability_validation import ValidationSuiteRepository; ValidationSuiteRepository('validation_cases').refresh_digests()"` 入正式套件。

规则侧结果（态势感知告警 + 受理回执）属步骤 03 采集范围，靶场阶段先人工记录窗口与 case-id 对应关系即可。

## 已知限制（PoC 接受）

- auditd 无文件 hash —— 锚点来自 collect.sh 工作区摘要清单（判定对象必须在剧本工作区落盘）；
- DNS / 字节数 / 文件读取不在探针范围（telemetry-scope.md）；
- t1547-006 依赖内核头；t1505-003 的 web 服务为 python 静态模拟，PHP 真实执行需靶机装 php-fpm（可后补）；
- 父进程关联依赖 ps 快照；窗口外进程（开机早于采集）无启动时间时按窗口内首次 exec 时间近似；
- 超长 EXECVE 参数被 auditd 拆分为 `a1[0]/a1[1]` 分片时当前不拼接（丢弃该参数，事件保留）；
- ps `lstart` 为靶机本地时区，跨时区靶机会使 process_ref 启动时间偏移（关联关系不受影响）；
- 被拒操作（EACCES/EPERM）在采集规则内但投影时丢弃（不产生幻影创建/连接证据）。

## 运行纪律（首轮实战教训，必读）

1. **审计规则短窗口装卸**：小规格靶机（≤1GB 内存）上全机 execve 规则与常驻 agent（安骑士/云监控）叠加，会把 audit backlog 顶到 8192 上限，触发内核背压——**所有**被审计 syscall 按 `backlog_wait_time`（60s）阻塞，全机假死、load 飙到 80+。纪律：跑 Case 前装规则、跑完立即 `auditctl -D` + 删规则文件；连续批量运行时每 3~4 个 Case 泄一次压（`auditctl -s` 看 backlog 接近上限即停手）。
2. **传输通道**：若 SFTP 被禁，bundle 走 base64 分块（exec 通道单行上限约 10KB 字符），已验证 4MB 包约 12 分钟；体积靠服务端噪音压缩控制（collect.sh 已内置）。
3. **轮询器必须可被 kill**：不要用 `( ... ) &` 子壳包装后台循环——kill 只能杀到子壳，泄漏的循环在弱机上就是负载事故；直接 `timeout N bash -c ... &` 并 kill 后补 `pkill -P`。
4. **靶机规格建议 ≥2C4G**；896MB 靶机可跑单 Case 验证链路，不适合连续批量。
