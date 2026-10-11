#!/usr/bin/env bash
# prepare（窗口外）：监听端就绪。回连脚本由攻击动作落盘（窗口内）。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
bash "$HERE/common/start_listener.sh" 8443
mkdir -p /tmp/.cache/beacon
printf "/tmp/.cache/beacon\n" > watch_paths.txt
: > approved_endpoints.txt
printf "/tmp/.cache/beacon/beacon.py\n" > system_paths.txt
