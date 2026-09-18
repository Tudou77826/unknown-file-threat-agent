---
name: linux-unknown-file
description: Investigation method for Linux unknown files, including execution, process ancestry, C2, persistence, counter-evidence, and closure requirements.
license: Internal
---

# Linux Unknown-File Investigation

## Investigation order

1. Confirm the file and host investigation anchors.
2. Activate `file_provenance` when the file's arrival mechanism is not already independently established.
3. Treat upstream process chains as claims until independent process events verify them.
4. Confirm actual execution before attributing runtime behavior.
5. Associate file-origin, network and persistence records using host, process start time, PID and file identity.
6. Check legitimate package provenance, approved endpoints and operations baselines.
7. Request finish only after every required active Evidence Role was attempted.

## Reference authorization (mandatory)

Every query is executed against exactly one authorized host and time window.
Two classes of identifiers exist and they are **not** interchangeable:

- **Context references** — entity IDs minted from the alert payload (e.g. a
  reported process chain). They describe what upstream *claimed*; they are not
  evidence and cannot be used as query input for raw records or metrics.
- **Authorized activity references** — activity IDs actually returned by a
  query in *this* run. Only these may be passed to `get_raw_records` and
  `calculate_activity_metrics`.

Consequence for planning: to inspect raw telemetry or compute metrics for a
process, first issue an activity query that returns it
(`query_process_activities`, `query_network_activities`, …), then reference the
returned activity IDs. Referencing context entity IDs directly is rejected by
the boundary and wastes a round.

Scope violations are rejected, never silently widened: a rejected call returns
`reference_not_authorized` with the reason. Read the reason and change your
next query rather than repeating the same call.

## Controlled scenario activation

- A model may activate only a scenario present in `activatable_scenarios`.
- Every activation must cite an existing Evidence, Fact or Finding ID.
- Activation loads a reviewed local Hypothesis, Evidence Role and EvidenceGap template; it does not create a Fact or Finding.
- Use `file_provenance` when the initial alert identifies the file but does not independently prove how it arrived.
- Do not activate the same scenario twice.

## File provenance investigation

Prefer `query_file_origin` when no mechanism is suspected; it checks all supported origin event types in the scoped host and time window. Select a narrower tool instead when existing case context already points to one mechanism or the broad source is unavailable:

- `query_file_downloads`: proxy, downloader or network-to-file correlation.
- `query_file_transfer`: SCP, SFTP, rsync or equivalent host/session transfer.
- `query_archive_extraction`: archive-to-file extraction lineage.
- `query_package_installation`: package transaction that installed the exact file.
- `query_web_upload_activity`: web process or upload session that wrote the file.

`analyze_file_provenance` deterministically creates origin Facts and Relations. Interpret the results carefully:

- A download, transfer, extraction or web upload establishes delivery; it does not prove maliciousness by itself.
- A signed trusted package supports a legitimate origin but does not override independently proven malicious runtime behavior.
- A file-create event proves which process wrote the file only when host, file identity and process instance match.
- An empty result supports a negative origin observation only when file telemetry Coverage is complete.
- When file telemetry is partial or unavailable, keep provenance unproven and record the limitation.

## Backdoor/C2 evidence requirements

- File execution is a prerequisite.
- Periodic communication is a suspicious Finding, not C2 proof by itself.
- Active persistence plus periodic external communication supports likely malicious.
- Confirmed malicious requires direct remote-command/task evidence in V1.
- A trusted signed package and approved endpoint can provide a benign explanation unless stronger contradictory evidence exists.

## Data-exfiltration investigation

Activate `data_exfiltration` only when an existing clue points to sensitive discovery/access, staging, unusual outbound bytes, upload behavior, or encoded DNS. Investigate separate evidence roles instead of treating any one indicator as exfiltration:

1. `query_discovery_commands` establishes reconnaissance intent but never proves collection.
2. `query_sensitive_file_access` must show a successful read/open/mmap/copy, not merely a pathname mention or denied access.
3. `query_archive_activity` or `query_staging_directory_activity` must connect sensitive source objects to a concrete transferable object.
4. `query_data_transfer`, `query_http_activity`, or `query_dns_payload_activity` must attribute egress to a process instance and destination.
5. `query_data_transfer_baseline` checks approved backup, monitoring, package-distribution, domain and destination explanations.
6. Run the scenario Analyzer that matches the channel. HTTPS confirmation requires the transmitted object to be the same staged object. DNS confirmation requires a process-attributed high-entropy sequence with payload and the sensitive staging chain.

Sensitive access alone is not theft. Archive creation alone is not staging of sensitive data. High outbound volume alone is not exfiltration. Encoded DNS alone is not malicious. Confirmed exfiltration requires an ordered, entity-linked chain and no matching approved baseline.

## Ransomware investigation

Separate attempted commands and suspicious bulk behavior from actual destructive impact:

1. Measure affected-file count, files per minute and directory breadth.
2. Require both content transformation evidence (entropy/header changes) and a consistent rename pattern before producing probable encryption.
3. Check whether backup deletion, snapshot destruction or service disruption actually succeeded; command text is not an outcome.
4. Correlate repeated ransom-note creation with the affected locations.
5. Query approved deployment, encryption rotation, compression, backup and log-rotation baselines.
6. Confirm ransomware only when execution, broad impact, encryption-like transformation, destructive/ransom impact and counter-evidence review form one attributed chain.

## Controlled cross-host investigation

- A candidate host must be explicitly named in cited evidence such as a successful file transfer. A shared endpoint alone is not propagation proof.
- Submit a `ScopeRequest`; never assume approval. Policy validates host grounding, minimal domains, time range and expansion budget.
- After approval, confirm hash presence, related authenticated access and target execution, then query asset/deployment context.
- A successful source-side transfer does not prove target execution. Approved fleet deployment is counter-evidence.
- When approval is pending or denied, record the target evidence gaps as unavailable and do not query target-only records.

## Prohibited reasoning

- Unknown does not mean malicious.
- Root execution, `/tmp`, SSH, shell, systemd and cron are not malicious independently.
- An empty query is not proof of absence unless Coverage is complete.
- Do not create Fact or Finding in the LLM; request an Analysis Tool.
- Do not invent a scenario, EvidenceRole or EvidenceGap outside the supplied activation catalog.
- Do not treat a trusted origin as proof that the running process was not injected, replaced or abused.

## Linux evidence-source checklist

Use this checklist to select Evidence Tools, not to execute shell commands or access the Agent runtime filesystem.

- Execution and ancestry: process start/exit records, exec telemetry, parent-child relations, process start time, executable identity and user identity.
- Authentication: SSH/PAM success and failure, sudo/su transitions, TTY/session identity, source address, account and key identifiers. Shell history is supporting context only because it can be absent or modified.
- Persistence: systemd unit write/enable/start, cron/at jobs, authorized keys, shell profiles, `rc.local`, init scripts, loader configuration and container restart policies. Configuration presence is not active persistence until activation or execution is observed.
- File behavior: create/read/write/rename/delete, content hashes, headers, entropy, archive lineage and affected-directory metrics. A pathname mention is not a successful access.
- Network: process-attributed connect/listen/socket I/O, DNS query sequence, HTTP upload result, byte counts and approved endpoint baseline.
- Containers: container and host PID mapping, image/digest, mounts, namespace, runtime events, entrypoint and container restart context. Do not attribute host activity from a container PID without identity mapping.
- Kubernetes: workload identity, namespace, pod/container, image digest, audit verb, API object, `exec`/`attach`, Secret access and ServiceAccount context. A pod name alone is not a stable identity.

## Alternative-source strategy

When the preferred source is missing, do not convert absence into a negative Fact. Use an eligible alternative source when it can answer the same Evidence Role:

- Missing file-read telemetry: archive membership, process open-file telemetry, staging lineage or application audit logs may support collection, but command text alone cannot confirm a read.
- Missing process ancestry: correlate executable identity, process start time, session and audit execution; keep attribution limited if PID reuse or boot identity is unresolved.
- Missing network process attribution: use endpoint flow plus socket/audit correlation; network flow alone cannot prove which process transmitted data.
- Missing systemd audit: combine unit content, file creation, enablement state and observed service execution; static unit presence alone is insufficient.
- Missing authentication logs: session, process ancestry, key use and source-host records can support a candidate path, but cannot confirm a login without an authentication outcome.
- Partial Coverage: request another source or preserve the EvidenceGap and limitation. Never state that behavior did not occur.

## Evidence Pack and repair discipline

- Each query produces an Evidence Pack describing its target Gap/Role, scope, returned Evidence, Coverage, limitations and AnalysisObligations.
- Prefer tools recommended by a blocking RepairAction before optional investigation.
- A complete empty Evidence Pack can resolve the requested question negatively only when the query covered every required alternative.
- An incomplete empty Evidence Pack requires an alternative source or an explicit unresolved limitation.
- A Validator repair may reopen a Gap, but it does not lower Analyzer thresholds or authorize invented Evidence.

## Investigation convergence

- Resolve critical required roles before optional context.
- Check at least one legitimate competing explanation for malicious chains.
- Avoid repeating a query with identical scope and parameters.
- Do not activate C2, exfiltration, ransomware or cross-host branches without a cited clue when an explicit scenario profile is already active.
- Near the budget limit, prioritize closure-blocking Gaps and report optional unknowns as limitations.
