#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# 良性：运维安装监控套件——二进制 + systemd 单元 + cron 同时出现（持久化风暴镜像）
"$HERE/common/build.sh" vendor-mon
cat > suite-manifest.json <<'EOS'
{"suite": "vendor-mon monitoring suite", "components": ["binary", "systemd unit", "cron report"],
 "installer": "ops-manual", "approved_by": "lab-ops"}
EOS
install -m 0755 vendor-mon /usr/local/bin/vendor-mon
cat > /etc/systemd/system/vendor-mon.service <<'EOS'
[Unit]
Description=Vendor Mon (SecVal lab ops suite)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/vendor-mon 127.0.0.1 8443
[Install]
WantedBy=multi-user.target
EOS
systemctl daemon-reload
systemctl enable vendor-mon.service >/dev/null 2>&1 || true
echo "5 4 * * * root /usr/local/bin/vendor-mon 127.0.0.1 8443" > /etc/cron.d/vendor-mon-report
"$HERE/common/with_listener.sh" 8443 /usr/local/bin/vendor-mon 127.0.0.1 8443
