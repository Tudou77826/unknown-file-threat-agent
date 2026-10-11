# 实验室执行手册（采集协议 v2 · 2026-10-12）

目标：29 案按 v2 协议全部重采 → 拉回本地沉淀 → 四类残留扫描全零 → 全量验证。

## 0. 前置确认（本地已就绪）

- [x] 29 案 prepare.sh/run.sh 齐备（ede3b2e），无回环 C2、无品牌残留
- [x] run_batch.sh v2（prepare→C2→规则→采集→清理），窗口内编译自检
- [x] settle v2（系统文件内容/去靶场化/台账反证/观测计数）
- [x] 410 测试绿

## 1. 上传（OpsCopilot exec，SFTP 不可用 → tar+base64 分块）

本地打包（排除 bundles/cases 产物）：

```bash
cd attack_lab && tar czf /tmp/lab-v2.tgz collector/ playbooks/ settle_case.py
# 分块上传后目标端重组（沿用 pull_bundles.sh 的反向操作，8KB 块）
```

目标端（/opt/secval-lab）：

```bash
cd /opt/secval-lab && tar xzf lab-v2.tgz   # 覆盖 collector/ 与 playbooks/
chmod +x collector/*.sh playbooks/common/*.sh playbooks/*/*.sh
```

## 2. 采集（目标端，约 40-60 分钟）

```bash
cd /opt/secval-lab && sudo bash collector/run_batch.sh \
  t1036-005-masquerade t1070-006-timestomp t1027-obfuscated-script \
  t1098-004-authorized-keys t1552-004-private-key t1548-001-setuid \
  t1059-006-python-beacon chain-001-full-intrusion t1136-001-account \
  t1005-t1560-001-archive t1037-004-rc-local t1053-003-cron-persistence \
  t1105-ingress-tool-transfer t1219-rat-tunnel t1486-ransomware \
  t1505-003-web-shell t1543-002-systemd-service t1547-006-kernel-module \
  t1567-002-exfil-upload t1574-006-ldpreload \
  bb2-admin-backup bb3-ops-tool-deploy bb4-ops-cron bb5-compiler-artifact \
  bb6-mirror-download bb7-vendor-agent bb8-ops-suite-install \
  bb9-log-rotation bb11-cfgmgmt-ssh-key 2>&1 | tee /tmp/batch.log
```

每案自检行必须人工过目：
- `编译=0` —— 非 0 即穿帮（prepare 泄漏进窗口），该案作废需排查
- `轮询=` 非零（回连类案）；`自身路径≥1`；`文件创建` 与场景相当
- `PREPARE FAILED` / `RULES_LOAD_FAILED` 的案重跑单案：`run_batch.sh <case-id>`

## 3. 拉回（目标端打包 → 本地 pull）

```bash
# 目标端
cd /opt/secval-lab/bundles && tar czf /tmp/bundles_v2.tgz *.bundle
# 本地：bash attack_lab/collector/pull_bundles.sh（沿用，改目标为 bundles_v2.tgz）
# 解到 attack_lab/bundles_v2/
```

## 4. 本地沉淀（29 案）

```bash
for 案: .venv/Scripts/python.exe attack_lab/settle_case.py \
  --source attack_lab/playbooks/<kind>/<case> \
  --bundle attack_lab/bundles_v2/<case>.bundle \
  --host-id server-01 --suite validation_cases_staging
```

## 5. 四类残留扫描（必须全零）

```text
① secval/SecVal 字样（含 case.json/input.json/事件）
② lab-vm / lab 字样主机名
③ 127.0.0.1 作为 C2/外连目标（ssh 本机验证除外）
④ 窗口内编译链（gcc/cc1/ld/build.sh 出现在事件里）
```

## 6. 全量验证（epochs=2）

```bash
.venv/Scripts/python.exe -m threat_agent.bootstrap.eval_cli \
  --name r12-validation-v2 --suite validation --fresh --epochs 2 --workers 3 --timeout 3600
```

验收线：恶意方向正确率 ≥85%；dist ≥0.75；match ≥0.95；demo 套件回归不降（0.80/1.0 基线）。

## 7. 已知事项

- t1547（内核模块）：目标机若启用模块签名，insmod 失败痕迹本身即证据，GT 预期不变
- bb11 仍为文档级部署记录（无真实 ansible 执行）——按复核意见保留标注
- 端点批准基线：良性案登记 198.51.100.50:8443（或下载端口）；恶意案空=未知
- 若 198.51.100.50 与靶机现有地址冲突：改 SECLAB_C2_IP 环境变量（三处脚本均读它）
