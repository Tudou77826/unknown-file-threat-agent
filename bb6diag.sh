#!/usr/bin/env bash
set -x
ls -la /tmp/secval-mirror-tool
python3 -m http.server 18083 --directory /tmp >/tmp/srv.log 2>&1 &
SRV=$!
sleep 2
ss -tlnp | grep 18083 || echo NO_LISTENER
curl -v -o /tmp/dl-test http://127.0.0.1:18083/secval-mirror-tool 2>&1 | tail -8
ls -la /tmp/dl-test 2>/dev/null
kill $SRV 2>/dev/null
cat /tmp/srv.log | head -5
