#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 良性：内部镜像下载工具 + 执行（镜像端点在批准清单）
"$HERE/common/build.sh" /tmp/secval-mirror-tool
python3 -m http.server 18082 --directory /tmp >/dev/null 2>&1 &
SRV=$!; sleep 0.5
curl -sf -o mirror-tool http://127.0.0.1:18082/secval-mirror-tool && chmod 700 mirror-tool
kill $SRV 2>/dev/null || true
./mirror-tool 2>/dev/null || ./mirror-tool 127.0.0.1 8443 || true
