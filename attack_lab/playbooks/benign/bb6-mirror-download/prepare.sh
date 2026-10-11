#!/usr/bin/env bash
# prepare（窗口外）：运维前置就绪（编译/数据/基线），窗口内只有运维动作。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
bash "$HERE/common/build.sh" /tmp/.seclab-recv-mirror/mirror-tool.elf 2>/dev/null || {
  mkdir -p /tmp/.seclab-recv-mirror; bash "$HERE/common/build.sh" /tmp/.seclab-recv-mirror/mirror-tool.elf; }
bash "$HERE/common/post_receiver.sh" 18086 /tmp/.seclab-recv-mirror
printf "" > watch_paths.txt
printf "%s\n" "$C2_IP" > approved_endpoints.txt
printf "/usr/local/bin/ops-mirror-tool\n" > system_paths.txt
