#!/usr/bin/env bash
# 从靶场分块回传 bundle（exec 通道输出上限 ~10KB，SFTP 不可用）。
# 用法: pull_bundles.sh <case-id>...  （产物落 ./bundles_b2/<case-id>.bundle/）
set -uo pipefail
OPS="/d/dev/workspace-go/OpsCopilot/build/bin/opscopilot.exe"
SERVER=39.108.66.227
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/bundles_b2"
CHUNK=8192
mkdir -p "$OUT_DIR"

export MSYS_NO_PATHCONV=1

for case_id in "$@"; do
  echo "== $case_id"
  meta_json=$("$OPS" exec --server $SERVER --command "cd /opt/secval-lab/bundles && tar czf /tmp/pull_${case_id}.tgz ${case_id}.bundle && base64 -w0 /tmp/pull_${case_id}.tgz > /tmp/pull_${case_id}.b64 && md5sum /tmp/pull_${case_id}.tgz | cut -d' ' -f1 && wc -c < /tmp/pull_${case_id}.b64" --intent "打包 bundle 准备分块回传" --timeout-sec 120 2>/dev/null | python -c "import json,sys; print(json.load(sys.stdin)['output'].strip())")
  md5=$(echo "$meta_json" | head -1)
  total=$(echo "$meta_json" | tail -1)
  if [ -z "$md5" ] || [ -z "$total" ]; then echo "  PACK FAIL"; continue; fi
  chunks=$(( (total + CHUNK - 1) / CHUNK ))
  echo "  md5=$md5 b64bytes=$total chunks=$chunks"
  tmp_b64=$(mktemp)
  for ((i = 0; i < chunks; i++)); do
    skip=$i
    "$OPS" exec --server $SERVER --command "dd if=/tmp/pull_${case_id}.b64 bs=$CHUNK skip=$skip count=1 2>/dev/null" --intent "回传 bundle 分块 $((i+1))/$chunks" --max-line-length 20000 --timeout-sec 60 2>/dev/null | python -c "import json,sys; sys.stdout.write(json.load(sys.stdin)['output'])" >> "$tmp_b64"
  done
  local_md5=$(base64 -d "$tmp_b64" 2>/dev/null | md5sum | cut -d' ' -f1)
  if [ "$local_md5" != "$md5" ]; then
    echo "  MD5 MISMATCH (local=$local_md5) — 重试该案"
    rm -f "$tmp_b64"
    continue
  fi
  base64 -d "$tmp_b64" > "$OUT_DIR/${case_id}.tgz"
  rm -f "$tmp_b64"
  tar xzf "$OUT_DIR/${case_id}.tgz" -C "$OUT_DIR" && rm -f "$OUT_DIR/${case_id}.tgz"
  echo "  OK -> $OUT_DIR/${case_id}.bundle"
  "$OPS" exec --server $SERVER --command "rm -f /tmp/pull_${case_id}.tgz /tmp/pull_${case_id}.b64" --intent "清理服务器临时文件" --timeout-sec 60 >/dev/null 2>&1 || true
done
echo "pull done"
