#!/usr/bin/env bash
# ops（窗口内）：运维健康检查工具部署与执行（无外连）。
set -euo pipefail
cat > /usr/local/bin/ops-healthcheck <<'EOS'
#!/usr/bin/env bash
echo "healthcheck ok" > /var/log/ops-health.txt
EOS
chmod 700 /usr/local/bin/ops-healthcheck
/usr/local/bin/ops-healthcheck
