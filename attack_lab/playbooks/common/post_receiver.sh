#!/usr/bin/env bash
# 采集协议 v2：支持 POST 上传并写回执的接收端（外传案的"成功回执"证据源）。
# 窗口外由 prepare 启动；GET 同目录可当下载源（chain 案首段 ingress 用）。
# 用法: post_receiver.sh <port> <serve-dir>
set -euo pipefail
PORT="${1:?port}"; SERVE="${2:?serve dir}"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
PIDFILE="/tmp/.seclab-receiver-$PORT.pid"
mkdir -p "$SERVE"

# 靶机为 python3.6：SimpleHTTPRequestHandler 的 directory= 参数是 3.7+ 才有，
# 用 os.chdir 兼容（否则每个请求处理器实例化即崩——rc=52 空回复的根因）
nohup python3 - "$C2_IP" "$PORT" "$SERVE" >/dev/null 2>&1 <<'PY' &
import http.server, socketserver, sys, time, os
ip, port, serve = sys.argv[1], int(sys.argv[2]), sys.argv[3]
os.chdir(serve)

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        name = os.path.join(serve, f"upload-{stamp}-{int(length)}B.bin")
        with open(name, "wb") as sink:
            sink.write(body)
        # 回执：落盘文件即"外传成功"的物证，同时响应体返回回执号
        receipt = f"RECV-{stamp}"
        with open(os.path.join(serve, "receipts.log"), "a") as log:
            log.write(f"{receipt} {length} {self.path}\n")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(receipt)))
        self.end_headers()
        self.wfile.write(receipt.encode())
    def log_message(self, *args):
        pass

socketserver.TCPServer.allow_reuse_address = True
with socketserver.ThreadingTCPServer((ip, port), Handler) as httpd:
    httpd.timeout = 600
    httpd.serve_forever()
PY
echo $! > "$PIDFILE"
sleep 0.3
for _ in $(seq 1 20); do
  ss -ltn 2>/dev/null | grep -q "$C2_IP:$PORT" && exit 0
  sleep 0.2
done
echo "RECEIVER NOT READY on $C2_IP:$PORT" >&2; exit 1
