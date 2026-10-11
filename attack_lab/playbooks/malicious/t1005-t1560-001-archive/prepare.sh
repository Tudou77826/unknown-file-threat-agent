#!/usr/bin/env bash
# prepare（窗口外）：编译与监听端就绪，攻击动作零发生。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
mkdir -p /tmp/.cache/stage
printf "/tmp/.cache/stage\n" > watch_paths.txt
: > approved_endpoints.txt
printf "/tmp/.cache/stage/staging.tar.gz\n" > system_paths.txt
