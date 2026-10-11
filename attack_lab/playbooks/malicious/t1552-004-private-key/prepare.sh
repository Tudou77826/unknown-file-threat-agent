#!/usr/bin/env bash
# prepare（窗口外）：造一把"已存在的"运维私钥（窃取对象）、起 POST 接收端。
# r11 复核整改：旧版现场 ssh-keygen 生成新钥冒充"窃取"——行为从未发生。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"

# 既有资产：运维用户 ops 的密钥（窗口外创建，遥测里只应有"被复制"而非"被创建"）
sudo mkdir -p /home/ops/.ssh
sudo chmod 700 /home/ops/.ssh
if [ ! -f /home/ops/.ssh/id_ed25519 ]; then
  sudo ssh-keygen -q -t ed25519 -N "" -f /home/ops/.ssh/id_ed25519 -C ops@inventory-2024
fi

# POST 接收端（窗口外起；回执是"外传成功"的物证）
bash "$HERE/common/post_receiver.sh" 18082 /tmp/.seclab-recv-1552

# 声明：投放目录监听 + 端点基线（恶意案：不登记任何端点=批准未知）
mkdir -p /tmp/.keydrop
cat > watch_paths.txt <<W
/tmp/.keydrop
W
: > approved_endpoints.txt
# 判定对象锚定：暂存私钥副本
cat > system_paths.txt <<S
/tmp/.keydrop/staged_id_rsa
S
