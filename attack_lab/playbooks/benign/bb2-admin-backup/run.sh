#!/usr/bin/env bash
# ops（窗口内）：应用数据定期备份。
set -euo pipefail
sudo tar czf /var/backups/admin/backup.tar.gz -C /opt appdata
