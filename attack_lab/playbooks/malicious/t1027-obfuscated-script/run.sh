#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# T1027：混淆载荷——base64 编码脚本落盘，运行时解码执行并外连
PAYLOAD="python3 -c 'import socket,time; s=socket.create_connection((\"127.0.0.1\",8443)); s.sendall(b\"secval-beacon\"); time.sleep(2)'"
printf '%s' "$PAYLOAD" | base64 -w0 > beacon.enc
"$HERE/common/with_listener.sh" 8443 bash -c "base64 -d beacon.enc | bash"
