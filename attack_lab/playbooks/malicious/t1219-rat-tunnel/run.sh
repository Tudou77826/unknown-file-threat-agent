#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# T1219：隧道部署 + 出站长连接
"$HERE/common/build.sh" tunnel.elf
"$HERE/common/with_listener.sh" 8443 ./tunnel.elf 127.0.0.1 8443 3000
