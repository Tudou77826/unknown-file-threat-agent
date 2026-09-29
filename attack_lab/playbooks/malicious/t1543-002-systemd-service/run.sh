#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# T1543.002：unit 写入 + enable + 服务式执行回连
"$HERE/common/build.sh" payload.elf
printf '[Unit]
Description=service helper
[Service]
ExecStart=%s/payload.elf 127.0.0.1 8443
[Install]
WantedBy=multi-user.target
' "$PWD" > /etc/systemd/system/secval-demo.service
ln -sf /etc/systemd/system/secval-demo.service /etc/systemd/system/multi-user.target.wants/secval-demo.service
"$HERE/common/with_listener.sh" 8443 ./payload.elf 127.0.0.1 8443
