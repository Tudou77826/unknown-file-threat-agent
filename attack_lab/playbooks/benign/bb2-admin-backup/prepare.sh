#!/usr/bin/env bash
# prepare（窗口外）：运维前置就绪（编译/数据/基线），窗口内只有运维动作。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
sudo mkdir -p /var/backups/admin /opt/appdata
echo "app-data" > /opt/appdata/data.db
printf "/var/backups/admin\n/opt/appdata\n" > watch_paths.txt
printf "" > approved_endpoints.txt
printf "/var/backups/admin/backup.tar.gz\n" > system_paths.txt
