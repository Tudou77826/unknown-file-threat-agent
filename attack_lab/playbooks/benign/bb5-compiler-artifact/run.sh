#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# 良性：编译 + 运行 + 连批准端点（127.0.0.1 在批准清单）
"$HERE/common/build.sh" demo.elf
"$HERE/common/with_listener.sh" 8443 ./demo.elf 127.0.0.1 8443
