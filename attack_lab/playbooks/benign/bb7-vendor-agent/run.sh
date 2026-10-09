#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# 良性：厂商监控 agent 定期回连（批准端点）并记录心跳
"$HERE/common/build.sh" vendor-agent
cat > deploy-manifest.json <<'EOS'
{"product": "SecVal Vendor Monitoring Agent", "version": "1.0", "vendor": "secval-lab",
 "approved_endpoint": "127.0.0.1:8443", "schedule": "every-2s-x3", "installed_by": "lab-ops"}
EOS
for i in 1 2 3; do
  date +%FT%T >> agent-heartbeat.txt
  "$HERE/common/with_listener.sh" 8443 ./vendor-agent 127.0.0.1 8443 1500
  sleep 1
done
