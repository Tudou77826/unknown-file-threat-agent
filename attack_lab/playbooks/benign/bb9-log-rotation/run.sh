#!/usr/bin/env bash
# ops（窗口内）：执行轮转并留存结果快照。
set -euo pipefail
/usr/local/bin/ops-rotate
ls -la /var/log/applog > rotation-result.txt 2>&1 || true
