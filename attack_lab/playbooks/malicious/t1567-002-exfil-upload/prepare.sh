#!/usr/bin/env bash
# prepare（窗口外）：编译与监听端就绪，攻击动作零发生。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
bash "$HERE/common/post_receiver.sh" 18081 /tmp/.seclab-recv-1567
mkdir -p /tmp/.cache/exfil
printf "/tmp/.cache/exfil\n" > watch_paths.txt
: > approved_endpoints.txt
printf "/tmp/.cache/exfil/exfil.tar.gz\n" > system_paths.txt
