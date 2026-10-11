#!/usr/bin/env bash
# prepare（窗口外）：运维前置就绪（编译/数据/基线），窗口内只有运维动作。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
bash "$HERE/common/build.sh" demo.elf
bash "$HERE/common/start_listener.sh" 8443
mkdir -p /opt/build
printf "/opt/build\n" > watch_paths.txt
printf "%s:8443\n" "$C2_IP" > approved_endpoints.txt
printf "/opt/build/demo.elf\n" > system_paths.txt
