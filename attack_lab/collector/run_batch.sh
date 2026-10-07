#!/usr/bin/env bash
# 分批补采执行器（复核后纪律版）：
#   逐案例：装审计规则 → 采集 → 立即卸规则 → 等积压排空
#   每案例自检：剧本 rc / 判定工件哈希 / 网络轮询命中 / 文件创建事件数
# 用法: run_batch.sh <case-id>...
set -uo pipefail
LAB=/opt/secval-lab
RULES_ON=0

rules_on()  { [ "$RULES_ON" = 0 ] && sudo cp $LAB/collector/audit-rules.conf /etc/audit/rules.d/secval.rules && sudo augenrules --load >/dev/null 2>&1 && RULES_ON=1 || true; }
rules_off() { sudo auditctl -D >/dev/null 2>&1; sudo rm -f /etc/audit/rules.d/secval.rules; RULES_ON=0; sleep 2; }
trap rules_off EXIT

for case_id in "$@"; do
  kind=malicious; [ -d "$LAB/playbooks/benign/$case_id" ] && kind=benign
  dir="$LAB/playbooks/$kind/$case_id"
  [ -f "$dir/run.sh" ] || { echo "== $case_id SKIP(no run.sh)"; continue; }

  echo "== $case_id ($kind)"
  rules_on
  sudo rm -rf "$LAB/cases/$case_id" "$LAB/bundles/$case_id.bundle"
  sudo bash $LAB/collector/collect.sh "$case_id" bash "$dir/run.sh" 2>&1 | tail -1
  rules_off

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
  echo "   工件=$hash_n 轮询=$poll_n 切片行=$audit_n 文件创建=$create_n"
  echo "   ---"
done
echo "batch done"
