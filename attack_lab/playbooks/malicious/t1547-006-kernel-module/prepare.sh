#!/usr/bin/env bash
# prepare（窗口外）：编译与监听端就绪，攻击动作零发生。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
KERN_BUILD="/lib/modules/$(uname -r)/build"
[ -d "$KERN_BUILD" ] || { echo "SKIP: kernel build dir unavailable"; exit 0; }
mkdir -p /tmp/.cache/lkm && cd /tmp/.cache/lkm
cat > rootkit.c <<'EOC'
#include <linux/module.h>
#include <linux/init.h>
MODULE_LICENSE("GPL");
static int __init rk_init(void){ return 0; }
static void __exit rk_exit(void){ }
module_init(rk_init);
module_exit(rk_exit);
EOC
printf 'obj-m += rootkit.o\n' > Makefile
make -C "$KERN_BUILD" M="$PWD" modules >/dev/null 2>&1 || echo "SKIP: kbuild failed"
cd - >/dev/null
printf "/tmp/.cache/lkm\n" > watch_paths.txt
: > approved_endpoints.txt
printf "/tmp/.cache/lkm/rootkit.ko\n" > system_paths.txt
