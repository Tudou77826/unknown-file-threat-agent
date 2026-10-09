#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# 良性：运维日志轮转——压缩归档旧日志并删除原件（清除/销毁行为镜像）
cat > rotation-policy.txt <<'EOS'
策略：/var/log/secval-demo 下超过 7 天的日志 gzip 归档至 /var/backups/secval-demo/ 后删除原件（运维轮转标准流程）。
EOS
sudo mkdir -p /var/log/secval-demo /var/backups/secval-demo
for i in 1 2 3; do echo "line-$i" | sudo tee /var/log/secval-demo/app.log.$i >/dev/null; done
sudo find /var/log/secval-demo -name 'app.log.*' -exec touch -d '30 days ago' {} +
cat > rotate.sh <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
find /var/log/secval-demo -name 'app.log.*' -mtime +7 -exec gzip {} \;
find /var/log/secval-demo -name 'app.log.*.gz' -exec mv {} /var/backups/secval-demo/ \;
find /var/log/secval-demo -name 'app.log.*' -mtime +7 -delete 2>/dev/null || true
EOS
chmod 750 rotate.sh
sudo ./rotate.sh
ls -la /var/log/secval-demo > rotation-result.txt 2>&1 || true
