#!/usr/bin/env bash
# 分批采集执行器（采集协议 v2，2026-10-12）：
#   逐案例：预构建（窗口外）→ 绑 C2 地址 → 装审计规则（含本案附加 watch）→
#           采集（仅攻击动作在窗）→ 卸规则 → 停监听 → 清残留 → 等积压排空
#   协议要点（r11 系列根因整改）：
#     · 编译/脚手架全部移出窗口——窗口内只有投放/执行/持久化/外连
#     · C2 地址为 lo 上绑定的非回环保留地址（默认 198.51.100.50），
#       遥测远端不再是 127.0.0.1
#     · 端点批准基线按案：剧本带 approved_endpoints.txt（良性登记 C2；
#       恶意不带=批准未知），不再全局一份把所有端点标成批准
#     · 剧本可声明 watch_paths.txt（投放目录等）追加审计监听
#   用法: run_batch.sh <case-id>...
set -uo pipefail
LAB=/opt/secval-lab
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
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
  # 本案附加 watch：投放目录等非基础监听路径（watch_paths.txt，绝对路径一行一个）
  local extra; extra=0
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    sudo auditctl -w "$p" -p wa -k secval 2>/dev/null && extra=$((extra+1)) || true
  done < "$LAB/cases/${CURRENT_CASE:-__none__}/watch_paths.txt" 2>/dev/null || true
  if [ "${n:-0}" -ge 5 ]; then RULES_ON=1; else
    echo "   RULES_LOAD_FAILED (loaded=${n:-0}) — 本案跳过，不产出空壳采集"; RULES_ON=0; fi
}
rules_off() { sudo auditctl -D >/dev/null 2>&1; sudo rm -f /etc/audit/rules.d/secval.rules; RULES_ON=0; sleep 2; }
c2_on()  { sudo ip addr add "$C2_IP/32" dev lo 2>/dev/null || true; }
c2_off() { sudo ip addr del "$C2_IP/32" dev lo 2>/dev/null || true; }
trap 'rules_off; c2_off' EXIT

for case_id in "$@"; do
  kind=malicious; [ -d "$LAB/playbooks/benign/$case_id" ] && kind=benign
  dir="$LAB/playbooks/$kind/$case_id"
  [ -f "$dir/run.sh" ] || { echo "== $case_id SKIP(no run.sh)"; continue; }

  echo "== $case_id"
  # 中性路径部署（r10 整改：命令行不得出现阵营词）
  neutral_dir="$LAB/run/$case_id"
  sudo rm -rf "$LAB/run"
  sudo mkdir -p "$neutral_dir" "$LAB/run/common"
  sudo cp "$dir/run.sh" "$neutral_dir/run.sh"
  [ -f "$dir/prepare.sh" ] && sudo cp "$dir/prepare.sh" "$neutral_dir/prepare.sh"
  [ -f "$dir/case.json" ] && sudo cp "$dir/case.json" "$neutral_dir/case.json"
  sudo cp "$LAB/playbooks/common/"*.sh "$LAB/run/common/" 2>/dev/null || true
  sudo cp "$LAB/playbooks/common/payload.c" "$LAB/run/common/" 2>/dev/null || true
  sudo sed -i "s#^HERE=.*#HERE=\"$LAB/run\"#" "$neutral_dir/run.sh"
  [ -f "$neutral_dir/prepare.sh" ] && sudo sed -i "s#^HERE=.*#HERE=\"$LAB/run\"#" "$neutral_dir/prepare.sh"

  CURRENT_CASE="$case_id"
  sudo rm -rf "$LAB/cases/$case_id" "$LAB/bundles/$case_id.bundle"
  sudo mkdir -p "$LAB/cases/$case_id"

  # 投放根目录预建（v2 剧本统一投放 /tmp/.cache/*；t1486/t1098 首跑实证
  # 各自 prepare 不会都建，缺目录时 cc/ssh-keygen 直接失败）
  sudo mkdir -p /tmp/.cache

  # ── prepare 阶段（窗口外：不装规则、不绑 C2 之后的动作不进遥测）──
  # 编译载荷、起监听器、登记端点基线与附加 watch 声明都发生在这里。
  if [ -f "$neutral_dir/prepare.sh" ]; then
    c2_on
    sudo bash -c "cd '$LAB/cases/$case_id' && SECLAB_C2_IP='$C2_IP' LAB_RUN_ROOT='$LAB/run' bash '$neutral_dir/prepare.sh'" \
      || { echo "   PREPARE FAILED — 本案跳过"; sudo bash "$LAB/run/common/stop_listener.sh" 8443 2>/dev/null || true; c2_off; echo "   ---"; continue; }
  fi

  rules_on
  [ "$RULES_ON" = 1 ] || { echo "   ---"; sudo bash "$LAB/run/common/stop_listener.sh" 8443 2>/dev/null || true; c2_off; continue; }
  sudo bash $LAB/collector/collect.sh "$case_id" bash "$neutral_dir/run.sh" 2>&1 | tail -1
  rules_off

  # 窗口后清理：停监听、卸 C2；系统残留清理可延迟（SECLAB_DEFER_CLEANUP=1）——
  # 2026-10-12 复核裁决第 4 条：本地"采到了+AI 能查到"双验证通过并保存完整采集包
  # 之后才执行 cleanup_all（残留物证保留待验，验证不过可立即复查现场）。
  # 纪律：延迟清理期间不得采集下一案（防跨案污染），逐案"采集→验证→清理→下一案"。
  for pf in /tmp/.seclab-listener-*.pid /tmp/.seclab-receiver-*.pid; do
    [ -f "$pf" ] && sudo kill "$(cat "$pf")" 2>/dev/null || true; sudo rm -f "$pf"
  done
  if [ "${SECLAB_DEFER_CLEANUP:-0}" != "1" ]; then
    sudo bash $LAB/collector/cleanup_all.sh >/dev/null 2>&1 || true
  else
    echo "   DEFER_CLEANUP: 残留保留待本地验证（通过后手动 cleanup_all.sh）"
  fi
  c2_off

  # 等待 auditd 排空积压
  for i in $(seq 1 10); do
    lost=$(sudo auditctl -s | awk '/^lost/{print $2}'); backlog=$(sudo auditctl -s | awk '/^backlog /{print $2}')
    [ "${backlog:-0}" -le 64 ] && break; sleep 2
  done

  B="$LAB/bundles/$case_id.bundle"
  hash_n=$(wc -l < "$B/workspace_hashes.txt" 2>/dev/null || true)
  poll_n=$(grep -c "ESTAB.*$C2_IP" "$B/conn_poll.log" 2>/dev/null || true)
  audit_n=$(wc -l < "$B/audit.log" 2>/dev/null || true)
  create_n=$(grep -c 'nametype=CREATE' "$B/audit.log" 2>/dev/null || true)
  # 自身路径断言：本案例工作区路径必须出现在审计记录里（防"采到别家的、漏掉自家的"）
  own_n=$(grep -c "secval-lab/cases/$case_id" "$B/audit.log" 2>/dev/null || true)
  # 出窗断言：窗口内不得出现编译链（prepare 泄漏检测——gcc/cc1/ld 出现即本例穿帮）
  build_n=$(grep -cE 'a[0-9]+="[^"]*gcc|comm="(gcc|cc1|ld|as)"|build\.sh' "$B/audit.log" 2>/dev/null || true)
  warn=""
  [ "${own_n:-0}" -lt 1 ] && warn="$warn ⚠自身路径缺失"
  [ "${build_n:-0}" -gt 0 ] && warn="$warn ⚠窗口内编译泄漏(${build_n})"
  echo "   工件=$hash_n 轮询=$poll_n 切片行=$audit_n 文件创建=$create_n 自身路径=$own_n 编译=$build_n$warn"
  echo "   ---"
done
echo "batch done"
