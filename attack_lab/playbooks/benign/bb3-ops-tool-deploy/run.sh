#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 良性：运维工具脚本部署与执行（无外连）
cat > ops-tool.sh <<'EOS'
#!/usr/bin/env bash
echo "healthcheck ok" > health.txt
EOS
chmod 700 ops-tool.sh && ./ops-tool.sh
