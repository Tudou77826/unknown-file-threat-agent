#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# T1548.001：setuid 提权——root 属主 + setuid 位的 helper 由非特权用户执行
"$HERE/common/build.sh" suid.elf
chown root:root suid.elf
chmod 4755 suid.elf
if command -v setpriv >/dev/null 2>&1; then
  AS=(setpriv --reuid=65534 --regid=65534 --clear-groups)
else
  AS=(runuser -u nobody --)
fi
"$HERE/common/with_listener.sh" 8443 "${AS[@]}" "$PWD/suid.elf" 127.0.0.1 8443 2> setuid-exec.txt || true
