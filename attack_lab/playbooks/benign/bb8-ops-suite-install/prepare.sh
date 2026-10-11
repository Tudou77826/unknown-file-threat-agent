#!/usr/bin/env bash
# prepare（窗口外）：运维前置就绪（编译/数据/基线），窗口内只有运维动作。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
bash "$HERE/common/build.sh" vendor-mon
bash "$HERE/common/start_listener.sh" 8443
sha256sum vendor-mon | awk '{print $1}' > vendor-mon.sha256
cat > suite-manifest.json <<EOS
{"suite": "vendor-mon monitoring suite", "installer": "ops-manual", "approved_by": "ops-team",
 "components": [
   {"kind": "binary", "path": "/usr/local/bin/vendor-mon", "sha256": "$(cat vendor-mon.sha256)"},
   {"kind": "systemd unit", "path": "/etc/systemd/system/vendor-mon.service"},
   {"kind": "cron report", "path": "/etc/cron.d/vendor-mon-report"}
 ],
 "approved_endpoint": "${C2_IP}:8443"}
EOS
printf "" > watch_paths.txt
printf "%s:8443\n" "$C2_IP" > approved_endpoints.txt
printf "/usr/local/bin/vendor-mon\n" > system_paths.txt
