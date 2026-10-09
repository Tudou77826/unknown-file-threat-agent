#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# T1036.005：后门伪装为系统程序名并放入合法系统目录执行
"$HERE/common/build.sh" payload.elf
install -m 0755 payload.elf /usr/local/sbin/sshd-helper
echo /usr/local/sbin/sshd-helper > system_paths.txt
"$HERE/common/with_listener.sh" 8443 /usr/local/sbin/sshd-helper 127.0.0.1 8443
