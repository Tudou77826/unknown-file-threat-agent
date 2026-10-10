#!/usr/bin/env bash
# 分批补采执行器（复核后纪律版）：
#   逐案例：装审计规则（带装载断言）→ 采集 → 立即卸规则 → 清系统残留 → 等积压排空
#   每案例自检：剧本 rc / 判定工件哈希 / 网络轮询命中 / 文件创建事件数 / 案例自身路径记录
# 用法: run_batch.sh <case-id>...
set -uo pipefail
LAB=/opt/secval-lab
RULES_ON=0

rules_on() {
  sudo cp $LAB/collector/audit-rules.conf /etc/audit/rules.d/secval.rules
  sudo augenrules --load >/dev/null 2>&1 || true
  # 装载断言：augenrules 偶发 No change 且规则未生效，直接采会产出空壳 bundle
  local n; n=$(sudo auditctl -l 2>/dev/null | grep -c '^-')
  if [ "${n:-0}" -lt 5 ]; then
    sudo auditctl -R /etc/audit/rules.d/secval.rules >/dev/null 2>&1 || true
    n=$(sudo auditctl -l 2>/dev/null | grep -c '^-')
  fi
  if [ "${n:-0}" -ge 5 ]; then RULES_ON=1; else
    echo "   RULES_LOAD_FAILED (loaded=${n:-0}) — 本案跳过，不产出空壳采集"; RULES_ON=0; fi
}
rules_off() { sudo auditctl -D >/dev/null 2>&1; sudo rm -f /etc/audit/rules.d/secval.rules; RULES_ON=0; sleep 2; }
trap rules_off EXIT

for case_id in "$@"; do
  kind=malicious; [ -d "$LAB/playbooks/benign/$case_id" ] && kind=benign
  dir="$LAB/playbooks/$kind/$case_id"
  [ -f "$dir/run.sh" ] || { echo "== $case_id SKIP(no run.sh)"; continue; }

  echo "== $case_id"
  # 2026-10-10 复核整改：命令行不得出现阵营词（playbooks/malicious|benign
  # 等于向模型泄露答案）。同步到中性 run/ 目录执行，HERE 重写为绝对路径，
  # 脚本内部 $HERE/common/... 引用保持同构。
  neutral_dir="$LAB/run/$case_id"
  sudo rm -rf "$LAB/run"
  sudo mkdir -p "$neutral_dir" "$LAB/run/common"
  sudo cp "$dir/run.sh" "$neutral_dir/run.sh"
  [ -f "$dir/case.json" ] && sudo cp "$dir/case.json" "$neutral_dir/case.json"
  sudo cp "$LAB/playbooks/common/"*.sh "$LAB/run/common/" 2>/dev/null || true
  sudo cp "$LAB/playbooks/common/payload.c" "$LAB/run/common/" 2>/dev/null || true
  sudo sed -i "s#^HERE=.*#HERE=\"$LAB/run\"#" "$neutral_dir/run.sh"
  rules_on
  [ "$RULES_ON" = 1 ] || { echo "   ---"; continue; }
  sudo rm -rf "$LAB/cases/$case_id" "$LAB/bundles/$case_id.bundle"
  sudo bash $LAB/collector/collect.sh "$case_id" bash "$neutral_dir/run.sh" 2>&1 | tail -1
  rules_off
  # 每案采后立即清残留：写入持久化项的案例（cron/密钥/账号）若不清，
  # 其驻留项会在后续案例的采集窗口内开火，造成跨案污染（chain cron 实证）
  sudo bash $LAB/collector/cleanup_all.sh >/dev/null 2>&1 || true

  # 等待 auditd 排空积压
  for i in $(seq 1 10); do
    lost=$(sudo auditctl -s | awk '/^lost/{print $2}'); backlog=$(sudo auditctl -s | awk '/^backlog /{print $2}')
    [ "${backlog:-0}" -le 64 ] && break; sleep 2
  done

  B="$LAB/bundles/$case_id.bundle"
  rc_line=$(tail -1 "$B/../$case_id.bundle/playbook.log" 2>/dev/null | head -c 60)
  hash_n=$(wc -l < "$B/workspace_hashes.txt" 2>/dev/null || echo 0)
  poll_n=$(grep -c "ESTAB.*127.0.0.1:844[3]" "$B/conn_poll.log" 2>/dev/null || echo 0)
  audit_n=$(wc -l < "$B/audit.log" 2>/dev/null || echo 0)
  create_n=$(grep -c 'nametype=CREATE' "$B/audit.log" 2>/dev/null || echo 0)
  # 自身路径断言：本案例工作区路径必须出现在审计记录里（防"采到别家的、漏掉自家的"）
  own_n=$(grep -c "secval-lab/cases/$case_id" "$B/audit.log" 2>/dev/null || echo 0)
  warn=""
  [ "${own_n:-0}" -lt 1 ] && warn="⚠自检失败:案例自身路径记录缺失"
  echo "   工件=$hash_n 轮询=$poll_n 切片行=$audit_n 文件创建=$create_n 自身路径=$own_n $warn"
  echo "   ---"
done
echo "batch done"
