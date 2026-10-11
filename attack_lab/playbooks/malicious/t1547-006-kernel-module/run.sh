#!/usr/bin/env bash
# attack（窗口内）：内核模块装载（被签名策略拒绝时留下失败痕迹即证据）。
set -euo pipefail
insmod /tmp/.cache/lkm/rootkit.ko 2> /tmp/.cache/lkm/insmod-err.txt || true
lsmod | grep -q rootkit && echo loaded
rmmod rootkit 2>/dev/null || true
