#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# T1005+T1560.001：敏感目录聚合归档
mkdir -p sensitive; echo "root:$6$salt$hash" > sensitive/shadow.extract; echo "ak=SK123" > sensitive/cloud.creds
tar czf staging.tar.gz sensitive
