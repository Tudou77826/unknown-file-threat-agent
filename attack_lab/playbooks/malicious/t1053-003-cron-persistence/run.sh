#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# T1053.003：cron 写入 + 手动触发一次（窗口内产事件）
"$HERE/common/build.sh" payload.elf
echo "* * * * * root $PWD/payload.elf 127.0.0.1 8443" > /etc/cron.d/secval-demo
"$HERE/common/with_listener.sh" 8443 ./payload.elf 127.0.0.1 8443
