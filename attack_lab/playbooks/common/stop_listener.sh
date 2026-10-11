#!/usr/bin/env bash
# 采集协议 v2：停止 start_listener 起的监听器（窗口外清理阶段调用）。
set -uo pipefail
PORT="${1:?port}"
PIDFILE="${SECLAB_LISTENER_PIDFILE:-/tmp/.seclab-listener-$PORT.pid}"
[ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
rm -f "$PIDFILE"
