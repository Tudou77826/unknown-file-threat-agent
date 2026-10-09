#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# T1059.006：Python 解释器执行驻留回连脚本
cat > beacon.py <<'PY'
import socket, time
for _ in range(3):
    try:
        s = socket.create_connection(("127.0.0.1", 8443), timeout=3)
        s.sendall(b"secval-beacon")
        time.sleep(1.5)
        s.close()
    except OSError:
        pass
    time.sleep(1)
PY
"$HERE/common/with_listener.sh" 8443 python3 beacon.py
