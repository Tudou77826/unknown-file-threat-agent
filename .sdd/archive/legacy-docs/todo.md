# Todo

## Done in MVP

- Create project structure.
- Add table-like sample JSON inputs.
- Normalize `T_FILE_DETAILS` into `case_context`.
- Parse `DETAIL.context` and `DETAIL.context[].tree`.
- Join `T_PROCESS_CHAIN_HASH` by `pid + processName`.
- Convert process-chain signals into evidence.
- Convert abnormal events into evidence.
- Generate simple attack steps.
- Generate a first-pass verdict.

## Next

1. Confirm the real `DETAIL` JSON grammar.
2. Confirm whether `tree[]` order is child-to-parent or parent-to-child.
3. Confirm timestamp units for all time fields.
4. Confirm real values for `hashType`: `Black`, `White`, `Suspecious`, `Grey`, etc.
5. Confirm the upstream JSON/API contract. The agent should consume provided fields, not depend on direct table access.
6. Add unit tests for normalizer and process-chain enrichment.
7. Add `sample_loader_and_static_analyzer`.
8. Add company script-parser adapter.
9. Add Linux persistence analyzer for cron/systemd/SSH key/SUID/LD_PRELOAD.
10. Add company defense-evasion adapter.
11. Add network behavior correlation by host, PID, process name, and time window.
12. Improve attack-path ordering by time.
13. Improve scoring rules and avoid over-scoring repeated weak evidence.
