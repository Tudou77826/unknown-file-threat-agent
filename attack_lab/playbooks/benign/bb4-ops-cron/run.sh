#!/usr/bin/env bash
# ops（窗口内）：注册定时清理任务并执行一次。
set -euo pipefail
echo "0 2 * * * root /usr/local/bin/ops-logclean" > /etc/cron.d/ops-logclean
/usr/local/bin/ops-logclean
