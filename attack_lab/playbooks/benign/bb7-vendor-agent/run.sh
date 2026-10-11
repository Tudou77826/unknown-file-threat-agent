#!/usr/bin/env bash
# ops（窗口内）：安装厂商 agent 并按清单声明的间隔（2s×3）心跳回连批准端点。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
install -m 0755 vendor-agent /usr/local/bin/vendor-agent
for i in 1 2 3; do
  date +%FT%T >> /var/log/vendor-agent-heartbeat.txt
  /usr/local/bin/vendor-agent "$C2_IP" 8443 1500
  [ "$i" = 3 ] || sleep 2
done
