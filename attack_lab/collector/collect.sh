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

# 环境基线快照（§10 端口 / 包清单；批准端点按案提供）
ss -ltnp > "$BUNDLE/listening_ports.txt" 2>/dev/null || true
ss -tnp   > "$BUNDLE/connections.txt" 2>/dev/null || true
rpm -qa   > "$BUNDLE/rpm_inventory.txt" 2>/dev/null || dpkg-query -W -f '${Package}\n' > "$BUNDLE/rpm_inventory.txt" 2>/dev/null || true
# 端点批准基线（协议 v2 按案化）：剧本 prepare 写入 WORK/approved_endpoints.txt
# （良性案登记 C2 地址；恶意案写空文件=批准情况未知）。缺省回退实验室全局清单。
if [ -s "$WORK/approved_endpoints.txt" ] || [ -f "$WORK/approved_endpoints.txt" ]; then
  cp "$WORK/approved_endpoints.txt" "$BUNDLE/approved_endpoints.txt"
else
  cp "${SECLAB_APPROVED_ENDPOINTS:-$LAB_ROOT/approved_endpoints.lab.txt}" "$BUNDLE/approved_endpoints.txt" 2>/dev/null || : > "$BUNDLE/approved_endpoints.txt"
fi
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

# 先切片再重快照：find/sha256/rpm 自身在全量审计规则下会产生洪流，
# 把剧本期记录挤出轮转卷（t1543/t1574 丢失根因）——趁记录还在当前卷立即切
sleep 3  # 等 auditd 落盘（高负载时写入滞后，立即切片会丢窗口尾部记录）
printf '%s\n%s\n' "$START_MS" "$END_MS" > "$BUNDLE/window.txt"

# 审计日志按窗口切片（毫秒级比较：整数秒会丢窗口首秒——剧本文件写入集中在一秒内）
awk -v s="$START_MS" -v e="$END_MS" '{
  if (match($0, /msg=audit\(([0-9]+)\.([0-9]+)/, k)) {
    ms = k[1] * 1000 + int(k[2])  # 小数部分本身就是毫秒（auditd 固定三位）
    if (ms >= s && ms <= e) print
  }
}' /var/log/audit/audit.log /var/log/audit/audit.log.[1-4] 2>/dev/null > "$BUNDLE/audit.log" || true
[ -s "$BUNDLE/audit.log" ] || echo "WARN: audit window slice is empty" >&2
# 窗口切片的类型统计（诊断用：类型缺失即可发现规则未装载/过滤过紧）
awk -F'type=' '/type=/{split($2,a," "); c[a[1]]++} END{for(k in c) print k, c[k]}' "$BUNDLE/audit.log" 2>/dev/null | sort > "$BUNDLE/audit_stats.txt" || true

# 噪音压缩：宿主常有高频背景活动（安骑士/面板），仅保留 Case 相关审计组：
# 命中 Case 路径 / 持久化路径 / USER_* / connect 的记录，按 serial 带上伴随记录
if [ -s "$BUNDLE/audit.log" ]; then
  # 原始窗口切片留存（诊断用：过滤误伤可离线复核）
  gzip -c "$BUNDLE/audit.log" > "$BUNDLE/audit.raw.log.gz"
  # 协议 v2：剧本声明 watch_paths.txt（投放目录等绝对路径，一行一个），
  # 过滤器的绝对名匹配动态并入——否则 /tmp/.xxx 投放记录会被基础规则漏掉
  EXTRA_WATCH=""
  if [ -f "$WORK/watch_paths.txt" ]; then
    while IFS= read -r wp; do
      [ -n "$wp" ] && EXTRA_WATCH="$EXTRA_WATCH|${wp//\//\\/}"
    done < "$WORK/watch_paths.txt"
  fi
  # 两遍扫描：SYSCALL 是每个事件的第一行，而序号命中靠后面的 PATH/CWD——
  # 单遍流式会在序号入集合前放走 SYSCALL 行（此前系统性丢失文件/执行 SYSCALL 的根因）
  # 保留判定（按序号）：
  #   a. PATH 绝对名命中监视路径（secval-lab 树 / etc 关键文件 / authorized_keys / usr/local/sbin）
  #   b. 相对 PATH 名 + 组 CWD 在案例目录下（相对路径执行 ./payload 的 exec 组只有相对名——
  #      按绝对名匹配会整个丢失载荷执行记录，bb7/t1059 实证）
  #   c. connect / USER_* 兜底（低频全捕）
  # 丢弃：comm="ss"（轮询器自身 netlink connect 命中兜底；ss 作为被调查对象不现实）
  gawk -v extra="$EXTRA_WATCH" '
    NR == FNR {
      if (match($0, /audit\([0-9.]+:([0-9]+)\)/, k)) {
        s = k[1]
        if ($0 ~ /comm="ss"/) drop[s] = 1
        if ($0 ~ /^type=CWD/ && match($0, /cwd="([^"]*)"/, c)) cwd[s] = c[1]
        if ($0 ~ /name="[^"]*(secval-lab|\/etc\/(systemd|cron|rc\.d|passwd|shadow)|authorized_keys|\/usr\/local\/sbin|\/usr\/local\/bin|\.ssh\/authorized_keys|\/var\/log\/secval-demo)/) keep[s] = 1
        else if (extra != "" && index($0, "name=\"") && $0 ~ ("name=\"[^\" ]*(" substr(extra, 2) ")")) keep[s] = 1
        else if ($0 ~ /^type=PATH/ && $0 !~ /name="\//) pend[s] = 1
        # EXECVE 带相对参数且组 CWD 在案例目录下：解释器执行案例脚本/载荷的形态
        # （python3 beacon.py）；采集器自身工具不适用（黑名单防自噪音回潮）
        if ($0 ~ /^type=EXECVE/ && $0 ~ /a[0-9]+="[^\/"][^"]*"/) pendexe[s] = 1
        if ($0 ~ /^type=SYSCALL/ && match($0, /comm="([^"]*)"/, cm)) ecomm[s] = cm[1]
        if ($0 ~ /type=USER_|syscall=42|type=USER_ACCT/) keep[s] = 1
      }
      next
    }
    {
      if (match($0, /audit\([0-9.]+:([0-9]+)\)/, k)) {
        s = k[1]
        if ((s in pend) && (s in cwd) && cwd[s] ~ /^\/opt\/secval-lab\/cases\//) keep[s] = 1
        if ((s in pendexe) && (s in cwd) && cwd[s] ~ /^\/opt\/secval-lab\/cases\// && !((s in ecomm) && ecomm[s] ~ /^(ss|date|sleep|pkill|gawk|awk|find|sha256sum|tar|ps|rpm|dpkg-query|gzip|dd|cut|wc|grep|sort|head|tail|cat|mkdir|rm|ls|env)$/)) keep[s] = 1
        if ((s in keep) && !(s in drop)) print
      }
    }
  ' "$BUNDLE/audit.log" "$BUNDLE/audit.log" > "$BUNDLE/audit.tmp" && mv "$BUNDLE/audit.tmp" "$BUNDLE/audit.log"
fi

# 工件快照与哈希清单（判定对象锚点来源：保留执行时真实字节；放在切片之后）
find "$WORK" -type f ! -name '*.log' -printf '%P\n' 2>/dev/null | sort > "$BUNDLE/workspace_files.txt" || \
  find "$WORK" -type f ! -name '*.log' | sed "s|^$WORK/||" | sort > "$BUNDLE/workspace_files.txt"
( cd "$WORK" && tar czf "$BUNDLE/workspace.tar.gz" --exclude='*.log' . 2>/dev/null || true )
( cd "$WORK" && find . -type f ! -name '*.log' -exec sha256sum {} \; | sort -k2 > "$BUNDLE/workspace_hashes.txt" )

# 判定对象在系统路径的剧本（伪装/密钥/账号案）：剧本在窗口内写 system_paths.txt
# 声明触碰过的系统文件，采集器记录其哈希供 settle 回退锚定（与工作区清单同构）
if [ -f "$WORK/system_paths.txt" ]; then
  : > "$BUNDLE/system_hashes.txt"
  while IFS= read -r p; do
    [ -n "$p" ] && [ -f "$p" ] && sha256sum "$p" >> "$BUNDLE/system_hashes.txt" || echo "WARN: system path missing $p" >&2
  done < "$WORK/system_paths.txt"
  # 协议 v2：系统文件内容快照（窗口后抓取）。t1136 复核实证：/etc/passwd 写入了
  # 什么（UID 0 账号）是定性关键，但此前只有"被写过"的事件没有内容——
  # AI 只能看到"useradd 改了 passwd"，与合法建账号无法区分。
  # 文本且 ≤16KB 才抓；路径映射存 manifest（文件名不可含 /）。
  mkdir -p "$BUNDLE/system_contents"
  : > "$BUNDLE/system_contents/manifest.txt"
  while IFS= read -r p; do
    [ -n "$p" ] && [ -f "$p" ] || continue
    size=$(stat -c %s "$p" 2>/dev/null || echo 0)
    [ "$size" -le 16384 ] || continue
    if file -b "$p" 2>/dev/null | grep -qiE 'text|empty|json|script'; then
      flat=$(echo "$p" | sed 's#^/##; s#/#_#g')
      cp "$p" "$BUNDLE/system_contents/$flat"
      printf '%s\t%s\n' "$p" "$flat" >> "$BUNDLE/system_contents/manifest.txt"
    fi
  done < "$WORK/system_paths.txt"
fi

ps -eo pid,ppid,lstart,args --sort=pid > "$BUNDLE/ps_after.txt" 2>/dev/null || true
# §2 包归属反证：逐工件查询所属包（非包文件 → owns_file=false 负证据）
: > "$BUNDLE/workspace_owners.txt"
while IFS= read -r f; do
  [ -f "$WORK/$f" ] || continue
  owner=$(rpm -qf --queryformat '%{NAME}' "$WORK/$f" 2>/dev/null || true)
  case "$owner" in "" | "file "* | *"not owned"*) owner=NOT-OWNED ;; esac
  printf '%s\t%s\n' "$f" "$owner" >> "$BUNDLE/workspace_owners.txt"
done < "$BUNDLE/workspace_files.txt"

echo "bundle ready: $BUNDLE (rc=$rc)"
