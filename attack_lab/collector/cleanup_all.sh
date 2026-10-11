#!/usr/bin/env bash
# SecLab 演练后清理：还原剧本写入的系统路径（工作区产物保留供沉淀）。
# 在所有 Case 采集完成后执行一次；幂等，可重复运行。
set -uo pipefail

removed=()

rm_unit=/etc/systemd/system/secval-demo.service
if [ -e "$rm_unit" ]; then sudo rm -f "$rm_unit" && removed+=("$rm_unit"); fi
rm_link=/etc/systemd/system/multi-user.target.wants/secval-demo.service
if [ -L "$rm_link" ]; then sudo rm -f "$rm_link" && removed+=("$rm_link"); fi
for f in /etc/cron.d/secval-demo /etc/cron.d/secval-ops-clean /etc/cron.d/secval-chain /etc/cron.d/vendor-mon-report; do
  if [ -e "$f" ]; then sudo rm -f "$f" && removed+=("$f"); fi
done
# 第二批剧本的系统路径：伪装副本/套件部署/单元文件
for f in /usr/local/sbin/sshd-helper /usr/local/bin/vendor-mon /etc/systemd/system/vendor-mon.service /etc/systemd/system/multi-user.target.wants/vendor-mon.service; do
  if [ -e "$f" ] || [ -L "$f" ]; then sudo rm -f "$f" && removed+=("$f"); fi
done
# 演练密钥行：从 authorized_keys 中剔除带演练标记的行（文件仅含演练行时整个删除）
ak="$HOME/.ssh/authorized_keys"
if [ -f "$ak" ] && grep -q 'secval\|chain\|cfgmgmt\|ops-deploy' "$ak" 2>/dev/null; then
  if [ "$(grep -cv 'secval\|chain\|cfgmgmt\|ops-deploy' "$ak" 2>/dev/null || echo 0)" = "0" ]; then
    rm -f "$ak" && removed+=("$ak (仅演练行，整文件删除)")
  else
    sed -i '\#secval\|chain\|cfgmgmt\|ops-deploy#d' "$ak" && removed+=("$ak (清除了演练追加行)")
  fi
fi
# 演练隐藏账号
if id svcmaint >/dev/null 2>&1; then sudo userdel -f svcmaint 2>/dev/null && removed+=("account svcmaint"); fi
rm -rf /var/log/secval-demo && removed+=("/var/log/secval-demo")
rc=/etc/rc.d/rc.local
if [ -f "$rc" ] && sudo grep -q 'secval\|/opt/secval-lab/cases/.*/payload.elf' "$rc" 2>/dev/null; then
  sudo sed -i '\#secval\|/opt/secval-lab/cases#d' "$rc" && removed+=("$rc (清除了演练追加行)")
fi
if lsmod 2>/dev/null | grep -q secval; then sudo rmmod rootkit 2>/dev/null && removed+=("kernel module rootkit"); fi

echo "cleanup removed ${#removed[@]} item(s):"
printf '  %s\n' "${removed[@]:-无残留}"
# 自检：确认无演练残留
leftover=""
[ -e "$rm_unit" ] && leftover="$leftover $rm_unit"
[ -e "$rm_link" ] && leftover="$leftover $rm_link"
for f in /etc/cron.d/secval-demo /etc/cron.d/secval-ops-clean /etc/cron.d/secval-chain /etc/cron.d/vendor-mon-report; do
  [ -e "$f" ] && leftover="$leftover $f"
done
for f in /usr/local/sbin/sshd-helper /usr/local/bin/vendor-mon /etc/systemd/system/vendor-mon.service; do
  [ -e "$f" ] && leftover="$leftover $f"
done
if id svcmaint >/dev/null 2>&1; then leftover="$leftover account:svcmaint"; fi
if [ -n "$leftover" ]; then echo "SELF-CHECK FAILED, still present:$leftover"; exit 1; fi
echo "self-check ok: no lab residue in system paths"

# ── 采集协议 v2（2026-10-12）新增残留 ──
for f in /etc/cron.d/sysupd-maint; do
  [ -e "$f" ] && sudo rm -f "$f" && removed+=("$f")
done
for d in /tmp/.sysupd /tmp/.keydrop /tmp/.seclab-recv-1552 /tmp/.seclab-recv-chain; do
  [ -d "$d" ] && sudo rm -rf "$d" && removed+=("$d")
done
sudo ip addr del 198.51.100.50/32 dev lo 2>/dev/null || true
