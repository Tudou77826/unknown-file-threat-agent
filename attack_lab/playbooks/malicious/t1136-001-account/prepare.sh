#!/usr/bin/env bash
# prepare（窗口外）：编译与监听端就绪，攻击动作零发生。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
printf "" > watch_paths.txt
: > approved_endpoints.txt
printf "/etc/passwd\n/etc/shadow\n" > system_paths.txt
