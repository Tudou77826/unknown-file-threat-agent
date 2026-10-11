#!/usr/bin/env bash
# prepare（窗口外）：编译与监听端就绪，攻击动作零发生。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
bash "$HERE/common/build.sh" drop.elf
bash "$HERE/common/start_listener.sh" 8443
mkdir -p /tmp/.seclab-recv-1105 /tmp/.cache/ingress
cp drop.elf /tmp/.seclab-recv-1105/tool.elf
bash "$HERE/common/post_receiver.sh" 18085 /tmp/.seclab-recv-1105
printf "/tmp/.cache/ingress\n" > watch_paths.txt
: > approved_endpoints.txt
printf "/tmp/.cache/ingress/payload.elf\n" > system_paths.txt
