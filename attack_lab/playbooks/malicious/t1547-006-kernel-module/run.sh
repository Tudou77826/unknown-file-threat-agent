#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# T1547.006：.ko + insmod（需靶机内核头；不可用则跳过本剧本）
if ! command -v cc >/dev/null || [ ! -d /lib/modules/"$(uname -r)" ]; then echo "SKIP: kernel headers unavailable"; exit 0; fi
cat > kmod.c <<'EOC'
#include <linux/module.h>
#include <linux/init.h>
MODULE_LICENSE("GPL");
static int __init secval_init(void){ return 0; }
module_init(secval_init);
EOC
cc -O2 -shared -fPIC -o rootkit.ko kmod.c 2>/dev/null || echo "SKIP: kmod build failed"
[ -f rootkit.ko ] && insmod rootkit.ko 2>/dev/null || true
