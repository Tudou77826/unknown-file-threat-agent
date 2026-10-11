#!/usr/bin/env bash
# prepare（窗口外）：运维前置就绪（编译/数据/基线），窗口内只有运维动作。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
# 旧日志与策略窗口外就位（造旧动作出窗——v1 伪影修复）
sudo mkdir -p /var/log/applog /var/backups/applog
for i in 1 2 3; do echo "line-$i" | sudo tee /var/log/applog/app.log.$i >/dev/null; done
sudo find /var/log/applog -name 'app.log.*' -exec touch -d '30 days ago' {} +
cat > rotation-policy.txt <<'EOS'
策略：/var/log/applog 下超过 7 天的日志 gzip 归档至 /var/backups/applog/ 后删除原件（运维轮转标准流程，归档保留）。
EOS
cat > /usr/local/bin/ops-rotate <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
find /var/log/applog -name 'app.log.*' -mtime +7 -exec gzip {} \;
find /var/log/applog -name 'app.log.*.gz' -exec mv {} /var/backups/applog/ \;
find /var/log/applog -name 'app.log.*' -mtime +7 -delete 2>/dev/null || true
EOS
chmod 750 /usr/local/bin/ops-rotate
printf "/var/log/applog\n/var/backups/applog\n" > watch_paths.txt
printf "" > approved_endpoints.txt
printf "/usr/local/bin/ops-rotate\n" > system_paths.txt
