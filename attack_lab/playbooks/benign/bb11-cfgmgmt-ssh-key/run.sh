#!/usr/bin/env bash
# ops（窗口内）：按部署记录下发公钥并做一次登入验证。
set -euo pipefail
mkdir -p /root/.ssh; chmod 700 /root/.ssh
cat ops_ed25519.pub >> /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 -i ops_ed25519 root@127.0.0.1 true 2> ops-ssh.txt || true
