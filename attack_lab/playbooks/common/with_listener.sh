#!/usr/bin/env bash
# 在指定端口起一次性 TCP 监听器并运行命令——让 connect() syscall 以 success 落审计，
# 且连接保持足够时长（HOLD 秒）供 ss 轮询捕获四元组（accept 后立即 close 会触发 RST，
# 连接毫秒级消失，采集不到 ESTAB）。
# 用法: with_listener.sh <port> <command...>
set -euo pipefail
PORT="${1:?port}"; shift
HOLD="${SECLAB_LISTENER_HOLD:-3}"
python3 - "$PORT" "$HOLD" <<'PY' &
import socket, sys, time
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(4)
srv.settimeout(float(sys.argv[2]) + 10)
try:
    for _ in range(4):
        conn, _ = srv.accept()
        time.sleep(float(sys.argv[2]))  # hold the connection open for the poller
        conn.close()
except OSError:
    pass
PY
LISTENER=$!
sleep 0.3
"$@"
status=$?
wait $LISTENER 2>/dev/null || true
exit $status
