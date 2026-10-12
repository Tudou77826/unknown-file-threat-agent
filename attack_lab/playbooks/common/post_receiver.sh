#!/usr/bin/env bash
# 采集协议 v2.1：支持 POST 上传并写回执的接收端（外传案的"成功回执"证据源）。
# 窗口外由 prepare 启动；GET 同目录可当下载源（chain 案首段 ingress 用）。
#
# 2026-10-12 复核整改（用户裁决第 3 条）：回执必须证明"收到的就是这个包"——
# 解析 multipart 表单取上传文件本体，回执记录：回执号、接收时间、原始文件名、
# 文件字节数、SHA256。发送端归档哈希与回执哈希一致 → 收发对应成立。
# receipts.log 为制表符分隔：receipt_id<TAB>iso_time<TAB>filename<TAB>size<TAB>sha256
#
# 用法: post_receiver.sh <port> <serve-dir>
set -euo pipefail
PORT="${1:?port}"; SERVE="${2:?serve dir}"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
PIDFILE="/tmp/.seclab-receiver-$PORT.pid"
mkdir -p "$SERVE"

# 靶机为 python3.6：SimpleHTTPRequestHandler 的 directory= 参数是 3.7+ 才有，
# 用 os.chdir 兼容（否则每个请求处理器实例化即崩——rc=52 空回复的根因）
nohup python3 - "$C2_IP" "$PORT" "$SERVE" >/dev/null 2>&1 <<'PY' &
import http.server, socketserver, sys, time, os, hashlib
ip, port, serve = sys.argv[1], int(sys.argv[2]), sys.argv[3]
os.chdir(serve)


def parse_multipart_file(headers, body):
    """从 multipart 表单体中提取上传文件本体（filename、字节）。

    3.6 无可靠的 email 库 boundary 处理，手工解析：
    body = --B\r\n段头\r\n\r\n文件\r\n--B--；按 boundary 切分后找 filename 段，
    段尾去掉下一个 boundary 的前导 \r\n。
    """
    ctype = headers.get("Content-Type", "")
    if "boundary=" not in ctype:
        return None, body
    boundary = ("--" + ctype.split("boundary=", 1)[1].split(";", 1)[0].strip()).encode()
    for part in body.split(boundary):
        head, _, payload = part.partition(b"\r\n\r\n")
        if b"filename=" not in head:
            continue
        if payload.endswith(b"\r\n"):
            payload = payload[:-2]
        filename = ""
        for line in head.split(b"\r\n"):
            if b"filename=" in line:
                seg = line.split(b"filename=", 1)[1].strip()
                seg = seg.strip(b'"')
                filename = seg.decode("utf-8", "replace")
        return filename, payload
    return None, body


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        receipt = "RECV-" + time.strftime("%Y%m%d-%H%M%S") + "-%05d" % int(length)
        filename, payload = parse_multipart_file(self.headers, body)
        # 原始请求体全量留存（含表单包装）——复核比对用
        raw_name = os.path.join(serve, "upload-%s.raw" % time.strftime("%Y%m%d-%H%M%S"))
        with open(raw_name, "wb") as sink:
            sink.write(body)
        if filename is not None:
            size = len(payload)
            sha = hashlib.sha256(payload).hexdigest()
            parsed = os.path.join(
                serve, "recv-%s-%s" % (time.strftime("%H%M%S"), os.path.basename(filename) or "bin"))
            with open(parsed, "wb") as sink:
                sink.write(payload)  # 解析出的上传文件本体（与回执哈希对应）
            line = "%s\t%s\t%s\t%d\t%s\n" % (receipt, stamp, filename, size, sha)
        else:
            line = "%s\t%s\t%s\t%d\t%s\n" % (receipt, stamp, "(unparsed)", len(body), "-")
        with open(os.path.join(serve, "receipts.log"), "a") as log:
            log.write(line)
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
