#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# 良性：运维 cron 清理任务
cat > logclean.sh <<'EOS'
#!/usr/bin/env bash
find /var/log/secval-demo -name '*.log' -mtime +7 -delete 2>/dev/null || true
EOS
chmod 700 logclean.sh
echo "0 2 * * * root $PWD/logclean.sh" > /etc/cron.d/secval-ops-clean
./logclean.sh
