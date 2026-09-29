#!/usr/bin/env bash
# SecLab 演练后清理：还原剧本写入的系统路径（工作区产物保留供沉淀）。
# 在所有 Case 采集完成后执行一次；幂等，可重复运行。
set -uo pipefail

removed=()

rm_unit=/etc/systemd/system/secval-demo.service
if [ -e "$rm_unit" ]; then sudo rm -f "$rm_unit" && removed+=("$rm_unit"); fi
rm_link=/etc/systemd/system/multi-user.target.wants/secval-demo.service
if [ -L "$rm_link" ]; then sudo rm -f "$rm_link" && removed+=("$rm_link"); fi
for f in /etc/cron.d/secval-demo /etc/cron.d/secval-ops-clean; do
  if [ -e "$f" ]; then sudo rm -f "$f" && removed+=("$f"); fi
done
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
for f in /etc/cron.d/secval-demo /etc/cron.d/secval-ops-clean; do
  [ -e "$f" ] && leftover="$leftover $f"
done
if [ -n "$leftover" ]; then echo "SELF-CHECK FAILED, still present:$leftover"; exit 1; fi
echo "self-check ok: no lab residue in system paths"
