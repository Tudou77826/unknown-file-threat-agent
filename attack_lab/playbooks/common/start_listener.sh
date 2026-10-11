#!/usr/bin/env bash
# 采集协议 v2：一次性 TCP 监听器，生命周期由 prepare/cleanup 管理（窗口外）。
# 监听地址默认 C2_IP（绑定在 lo 上的非回环保留地址 198.51.100.50——遥测里的
# 远端地址呈现为真实样式的外部 IP，而非 127.0.0.1；r11 系列实证回环地址会被
# 模型当作头号良性证据）。
# 用法: start_listener.sh <port> [max_accepts=40] [hold_secs=2]
set -euo pipefail
PORT="${1:?port}"; ACCEPTS="${2:-40}"; HOLD="${3:-2}"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
PIDFILE="${SECLAB_LISTENER_PIDFILE:-/tmp/.seclab-listener-$PORT.pid}"

nohup python3 - "$C2_IP" "$PORT" "$ACCEPTS" "$HOLD" >/dev/null 2>&1 <<'PY' &
import socket, sys, time
ip, port, accepts, hold = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((ip, port))
srv.listen(8)
srv.settimeout(accepts * hold + 60)
try:
    for _ in range(accepts):
        conn, _ = srv.accept()
        time.sleep(hold)  # 保持连接供 ss 轮询捕获四元组
        conn.close()
except OSError:
    pass
PY
echo $! > "$PIDFILE"
sleep 0.3
# 就绪断言：端口起来才算 prepare 成功
for _ in $(seq 1 20); do
  ss -ltn 2>/dev/null | grep -q "$C2_IP:$PORT" && exit 0
  sleep 0.2
done
echo "LISTENER NOT READY on $C2_IP:$PORT" >&2; exit 1
