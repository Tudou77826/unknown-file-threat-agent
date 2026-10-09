#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# 良性：配置管理下发运维公钥到 authorized_keys（密钥驻留的完美镜像）
ssh-keygen -q -t ed25519 -N '' -f ops_ed25519 -C ops-deploy@cfgmgmt 2>/dev/null
cat > ansible-deploy.yaml <<'EOS'
# 运维公钥下发（配置管理）：密钥注释 ops-deploy@cfgmgmt，目标 root@lab
- name: deploy ops access key
  authorized_key:
    user: root
    key: "{{ lookup('file', 'ops_ed25519.pub') }}"
EOS
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
cat ops_ed25519.pub >> "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"
echo "$HOME/.ssh/authorized_keys" > system_paths.txt
ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 -i ops_ed25519 "${USER}@127.0.0.1" true 2> ops-ssh.txt || true
