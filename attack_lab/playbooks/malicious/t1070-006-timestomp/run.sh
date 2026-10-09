#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# T1070.006：时间戳篡改——回拨后门文件 mtime 至系统旧文件时间
"$HERE/common/build.sh" payload.elf
"$HERE/common/with_listener.sh" 8443 ./payload.elf 127.0.0.1 8443
touch -r /bin/ls ./payload.elf
stat ./payload.elf > timestomp-evidence.txt 2>&1 || true
