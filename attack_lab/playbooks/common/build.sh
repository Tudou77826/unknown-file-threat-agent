#!/usr/bin/env bash
# 编译标准载荷。用法: build.sh <out-name> [cc flags...]
# 编译产物落在剧本工作区（CWD），其 sha256 由 collect.sh 记录为判定锚点。
set -euo pipefail
OUT="${1:?output name}"; shift
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cc -O2 -Wall -o "$OUT" "$@" "$HERE/payload.c"
