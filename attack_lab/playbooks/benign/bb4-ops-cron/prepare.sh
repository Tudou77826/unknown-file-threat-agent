#!/usr/bin/env bash
# prepare（窗口外）：运维前置就绪（编译/数据/基线），窗口内只有运维动作。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
# 旧日志窗口外造好并做旧（运维环境本来就有的历史日志）——修复 v1 的
# "窗口内 touch -d 造旧"伪影（长得像时间戳篡改，出现在良性案里）
sudo mkdir -p /var/log/applog
for i in 1 2 3; do echo "line-$i" | sudo tee /var/log/applog/app.log.$i >/dev/null; done
sudo find /var/log/applog -name 'app.log.*' -exec touch -d '30 days ago' {} +
cat > /usr/local/bin/ops-logclean <<'EOS'
#!/usr/bin/env bash
find /var/log/applog -name 'app.log.*' -mtime +7 -delete 2>/dev/null || true
EOS
chmod 700 /usr/local/bin/ops-logclean
printf "/var/log/applog\n" > watch_paths.txt
printf "" > approved_endpoints.txt
printf "/usr/local/bin/ops-logclean\n" > system_paths.txt
