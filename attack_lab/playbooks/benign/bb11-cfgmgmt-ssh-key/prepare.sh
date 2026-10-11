#!/usr/bin/env bash
# prepare（窗口外）：运维前置就绪（编译/数据/基线），窗口内只有运维动作。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
# 密钥与部署记录窗口外备好（配置管理预生成密钥是标准做法）
ssh-keygen -q -t ed25519 -N '' -f ops_ed25519 -C ops-deploy@cfgmgmt 2>/dev/null
cat > ansible-deploy.yaml <<'EOS'
# 运维公钥下发（配置管理）：密钥注释 ops-deploy@cfgmgmt，目标 root@lab
- name: deploy ops access key
  authorized_key:
    user: root
    key: "{{ lookup('file', 'ops_ed25519.pub') }}"
EOS
printf '{"ticket": "OPS-2026-1013", "action": "deploy-ops-key", "key_comment": "ops-deploy@cfgmgmt", "approved_by": "ops-lead"}\n' > deploy-record.json
printf "" > watch_paths.txt
printf "" > approved_endpoints.txt
printf "/root/.ssh/authorized_keys\n" > system_paths.txt
