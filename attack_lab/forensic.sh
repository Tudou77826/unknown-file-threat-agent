#!/usr/bin/env bash
# 一次性取证脚本：payload execve 是否进审计、窗口分布、丢包计数
LOG=/var/log/audit/audit.log
echo "== auditctl 状态（丢包/溢出）"
auditctl -s | grep -E 'lost|backlog|rate' || true
echo "== payload.elf 的 EXECVE 记录（全日志，最近5条）"
grep -F 'payload.elf' "$LOG" | grep -F 'EXECVE' | tail -5 | cut -c1-160
echo "== payload 进程的 SYSCALL execve（通过 proctitle/comm 关联）"
grep -F 'comm="payload.elf"' "$LOG" | tail -3 | cut -c1-160
echo "== 1790665664-670 秒级记录数分布"
grep -oE 'msg=audit\(179066566[4-9]\.' "$LOG" | sort | uniq -c
echo "== run#4 窗口内（664.35-670.36）SYSCALL 数"
awk 'match($0, /msg=audit\(([0-9]+)\./, m) { if (m[1] >= 1790665664 && m[1] <= 1790665670) n++ } END { print n+0 }' "$LOG"
echo "== 最近一次 with_listener 的 python 监听 execve"
grep -F 'python3 -' "$LOG" | tail -2 | cut -c1-140
