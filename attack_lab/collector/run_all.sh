#!/usr/bin/env bash
# 批量执行全部剧本并打包所有 bundle 为单一 tgz 供下载。
set -uo pipefail
LAB=/opt/secval-lab
cd "$LAB"

for kind in malicious benign; do
  for dir in "$LAB/playbooks/$kind"/*/; do
    case_id=$(basename "$dir")
    [ -f "$dir/run.sh" ] || continue
    echo "== $kind/$case_id"
    rm -rf "cases/$case_id" "bundles/$case_id.bundle"
    bash collector/collect.sh "$case_id" bash "$dir/run.sh" 2>&1 | tail -1
  done
done

# 统一剥离富化后缀并打包
for b in bundles/*.bundle; do
  sed -i 's/\x1d.*$//' "$b/audit.log" 2>/dev/null || true
done
tar czf /tmp/lab-bundles.tgz -C bundles .
chmod 644 /tmp/lab-bundles.tgz
ls -la /tmp/lab-bundles.tgz
du -sh bundles/
