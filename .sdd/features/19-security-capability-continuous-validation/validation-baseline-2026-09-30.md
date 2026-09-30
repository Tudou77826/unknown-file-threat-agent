<!-- 归档自 outputs/eval/validation-baseline/report.md（2026-09-30，glm-5.3-flash，5 案例）。
解读：检出方向 100%（三个靶场恶意案例全部落在恶意侧、良性零误报）；
置信等级保守（suspicious 而非 confirmed）的根因已定位——靶场 replay 仅有 4 类事件，
持久化/文件写入证据在采集风暴期丢失（known issue），AI 在证据不足时拒绝确认属正确纪律；
手写 c2-malicious-elf（证据链完整）精确命中 confirmed_malicious 佐证。
补齐靶场 11 案例重采（含文件事件）后复跑即为完整技术覆盖基线。 -->

# SecAgent Eval — validation-baseline

- cases: 5 · runs: 5 · status: {'ok': 5}
- pass^k rate: 0.4 · tokens: 1103748 · mean duration: 1084.745s

| dimension | mean |
|---|---|
| distance | 0.76 |
| duration_seconds | 1084.745 |
| match | 1.0 |
| model_calls | 9.4 |
| side_correct | 1.0 |
| tool_calls | 18.0 |
| total_tokens | 220749.6 |

| case | tags | k | all epochs passed |
|---|---|---|---|
| c2-benign-baseline | baseline,family:validation,level:l3 | 1 | yes |
| c2-malicious-elf | T1071.001,T1543.002,family:validation,level:l3 | 1 | yes |
| t1037-004-rc-local | T1037.004,family:validation,level:l3 | 1 | NO |
| t1053-003-cron-persistence | T1053.003,family:validation,level:l3 | 1 | NO |
| t1105-ingress-tool-transfer | T1105,T1222.002,family:validation,level:l3 | 1 | NO |
