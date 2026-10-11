#!/usr/bin/env bash
# prepare（窗口外）：编译与监听端就绪，攻击动作零发生。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
sudo mkdir -p /var/www/html
# HTTP 服务窗口外起（web 服务器本来就在跑——不是攻击脚手架）
nohup python3 -m http.server 18080 --bind "$C2_IP" --directory /var/www/html >/dev/null 2>&1 &
echo $! > /tmp/.seclab-receiver-18080.pid
sleep 0.5
printf "/var/www/html\n" > watch_paths.txt
: > approved_endpoints.txt
printf "/var/www/html/shell.php\n" > system_paths.txt
