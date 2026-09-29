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

# 运行剧本（工作区内，产物落盘路径确定）
LOG="$BUNDLE/playbook.log"
if ! (cd "$WORK" && "$@" >"$LOG" 2>&1); then
  echo "PLAYBOOK FAILED (exit $?) — bundle retained for triage" | tee -a "$LOG"
fi
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
  printf '%s\t%s\n' "$f" "${owner:-NOT-OWNED}" >> "$BUNDLE/workspace_owners.txt"
done < "$BUNDLE/workspace_files.txt"
cp /var/log/audit/audit.log "$BUNDLE/audit.log" 2>/dev/null || \
  journalctl -k > "$BUNDLE/audit.log" 2>/dev/null || : > "$BUNDLE/audit.log"

echo "bundle ready: $BUNDLE"
