#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# T1105+T1222.002：外部拉取 → chmod → 执行回连
STAGING="${SECLAB_STAGING:-/tmp/secval-staging}"; "$HERE/common/build.sh" "$STAGING/payload.elf"
curl -sf -o payload.elf "file://$STAGING/payload.elf" || cp "$STAGING/payload.elf" payload.elf
chmod 700 payload.elf
"$HERE/common/with_listener.sh" 8443 ./payload.elf 127.0.0.1 8443
