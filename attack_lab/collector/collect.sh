#!/usr/bin/env bash
# SecLab 靶场采集编排：窗口标注 → 运行剧本 → 快照归档。
# 用法: collect.sh <case-id> <command...>
# 产物: /opt/secval-lab/bundles/<case-id>.bundle/ （scp 回执行机后交给 settle_case.py）
set -euo pipefail

CASE_ID="${1:?usage: collect.sh <case-id> <command...>}"; shift
LAB_ROOT="${SECLAB_ROOT:-/opt/secval-lab}"
WORK="$LAB_ROOT/cases/$CASE_ID"
BUNDLE="$LAB_ROOT/bundles/$CASE_ID.bundle"

mkdir -p "$WORK" "$BUNDLE"
START_MS=$(date +%s%3N)

# 环境基线快照（§10 端口 / 包清单；批准端点由 CMDB 导出文件提供）
ss -ltnp > "$BUNDLE/listening_ports.txt" 2>/dev/null || true
ss -tnp   > "$BUNDLE/connections.txt" 2>/dev/null || true
rpm -qa   > "$BUNDLE/rpm_inventory.txt" 2>/dev/null || dpkg-query -W -f '${Package}\n' > "$BUNDLE/rpm_inventory.txt" 2>/dev/null || true
cp "${SECLAB_APPROVED_ENDPOINTS:-$LAB_ROOT/approved_endpoints.txt}" "$BUNDLE/approved_endpoints.txt" 2>/dev/null || : > "$BUNDLE/approved_endpoints.txt"
# §1 进程谱系：pid/ppid/启动时间，供父进程关联与 process_ref 稳定化
ps -eo pid,ppid,lstart,args --sort=pid > "$BUNDLE/ps_before.txt" 2>/dev/null || true

# 网络轮询：auditd 的 connect 只留指针不留四元组，远端由 ss 轮询补齐
timeout 120 bash -c 'while :; do date +%s%3N; ss -tnp 2>/dev/null; echo ---; sleep 0.2; done' > "$BUNDLE/conn_poll.log" & POLLER=$!

# 运行剧本（工作区内，产物落盘路径确定）
LOG="$BUNDLE/playbook.log"
rc=0; (cd "$WORK" && "$@" >"$LOG" 2>&1) || rc=$?
kill "$POLLER" 2>/dev/null; sleep 0.1; pkill -P "$POLLER" 2>/dev/null || true
[ "$rc" -ne 0 ] && echo "PLAYBOOK FAILED (exit $rc) — bundle retained for triage" | tee -a "$LOG"
END_MS=$(date +%s%3N)

# 工件快照与哈希清单（判定对象锚点来源：保留执行时真实字节）
find "$WORK" -type f ! -name '*.log' -printf '%P\n' 2>/dev/null | sort > "$BUNDLE/workspace_files.txt" || \
  find "$WORK" -type f ! -name '*.log' | sed "s|^$WORK/||" | sort > "$BUNDLE/workspace_files.txt"
( cd "$WORK" && tar czf "$BUNDLE/workspace.tar.gz" --exclude='*.log' . 2>/dev/null || true )
( cd "$WORK" && find . -type f ! -name '*.log' -exec sha256sum {} \; | sort -k2 > "$BUNDLE/workspace_hashes.txt" )

printf '%s\n%s\n' "$START_MS" "$END_MS" > "$BUNDLE/window.txt"
ps -eo pid,ppid,lstart,args --sort=pid > "$BUNDLE/ps_after.txt" 2>/dev/null || true
# §2 包归属反证：逐工件查询所属包（非包文件 → owns_file=false 负证据）
: > "$BUNDLE/workspace_owners.txt"
while IFS= read -r f; do
  [ -f "$WORK/$f" ] || continue
  owner=$(rpm -qf --queryformat '%{NAME}' "$WORK/$f" 2>/dev/null || true)
  case "$owner" in "" | "file "* | *"not owned"*) owner=NOT-OWNED ;; esac
  printf '%s\t%s\n' "$f" "$owner" >> "$BUNDLE/workspace_owners.txt"
done < "$BUNDLE/workspace_files.txt"
# 等待 auditd 落盘（高负载时写入滞后，立即切片会丢窗口尾部记录）
sleep 3

# 审计日志按窗口切片（秒×1000 对齐毫秒窗口；传输与沉淀都只需要窗口内记录）
awk -v s="$START_MS" -v e="$END_MS" '{
  if (match($0, /msg=audit\([0-9]+/)) {
    sec = substr($0, RSTART + 10, RLENGTH - 10) + 0
    if (sec * 1000 >= s && sec * 1000 <= e) print
  }
}' /var/log/audit/audit.log /var/log/audit/audit.log.[1-4] 2>/dev/null > "$BUNDLE/audit.log" || true
[ -s "$BUNDLE/audit.log" ] || echo "WARN: audit window slice is empty" >&2

# 噪音压缩：宿主常有高频后台活动（安骑士/面板），仅保留 Case 相关审计组：
# 命中 Case 路径 / 持久化路径 / USER_* / connect 的记录，按 serial 带上伴随记录
if [ -s "$BUNDLE/audit.log" ]; then
  gawk '
    /secval-lab|\/etc\/(systemd|cron|rc\.d)|type=USER_|syscall=42|type=USER_ACCT/ {
      if (match($0, /audit\([0-9.]+:([0-9]+)\)/, k)) keep[k[1]] = 1
    }
    { if (match($0, /audit\([0-9.]+:([0-9]+)\)/, k) && (k[1] in keep)) print }
  ' "$BUNDLE/audit.log" > "$BUNDLE/audit.tmp" && mv "$BUNDLE/audit.tmp" "$BUNDLE/audit.log"
fi

echo "bundle ready: $BUNDLE (rc=$rc)"
