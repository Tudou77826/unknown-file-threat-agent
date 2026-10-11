#!/usr/bin/env bash
# prepare（窗口外）：运维前置就绪（编译/数据/基线），窗口内只有运维动作。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
bash "$HERE/common/build.sh" vendor-agent
bash "$HERE/common/start_listener.sh" 8443
cat > deploy-manifest.json <<EOS
{"product": "NetWatch Monitoring Agent", "version": "2.3.1", "vendor": "netwatch-ops",
 "binary": "vendor-agent", "approved_endpoint": "${C2_IP}:8443", "schedule": "every-2s-x3",
 "interval_seconds": 2, "repeat": 3, "installed_by": "ops-team"}
EOS
printf "" > watch_paths.txt
printf "%s:8443\n" "$C2_IP" > approved_endpoints.txt
printf "/usr/local/bin/vendor-agent\n" > system_paths.txt
