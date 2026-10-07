#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# 良性：从内部批准镜像下载运维工具并执行（下载失败必须显式失败，不做静默兜底）
"$HERE/common/build.sh" /tmp/secval-mirror-tool
( cd /tmp && python3 -m http.server 18082 >/dev/null 2>&1 ) &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
ok=""
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 0.5
  if curl -sf -o mirror-tool "http://127.0.0.1:18082/secval-mirror-tool"; then ok=1; break; fi
done
if [ -z "$ok" ]; then
  echo "MIRROR DOWNLOAD FAILED after 10 attempts" >&2
  exit 1
fi
chmod 700 mirror-tool
./mirror-tool 127.0.0.1 8443
