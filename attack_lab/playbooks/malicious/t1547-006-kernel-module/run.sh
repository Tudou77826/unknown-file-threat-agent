#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# T1547.006：内核模块——用 kbuild 正确编译（裸 cc 编不了内核模块）后 insmod
KERN_BUILD="/lib/modules/$(uname -r)/build"
if [ ! -d "$KERN_BUILD" ]; then echo "SKIP: kernel build dir unavailable"; exit 0; fi
cat > rootkit.c <<'EOC'
#include <linux/module.h>
#include <linux/init.h>
MODULE_LICENSE("GPL");
static int __init secval_init(void){ return 0; }
static void __exit secval_exit(void){ }
module_init(secval_init);
module_exit(secval_exit);
EOC
printf 'obj-m += rootkit.o
' > Makefile
if ! make -C "$KERN_BUILD" M="$PWD" modules >/dev/null 2>&1; then
  echo "SKIP: kbuild failed"; exit 0
fi
if ! sudo insmod rootkit.ko 2>/dev/null; then
  echo "SKIP: insmod rejected (unsigned module policy)"; exit 0
fi
lsmod | grep -q rootkit && echo "module loaded"
sudo rmmod rootkit 2>/dev/null || true
