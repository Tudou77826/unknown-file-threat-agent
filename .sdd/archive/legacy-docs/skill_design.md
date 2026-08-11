# Skill Design

The project goal is unknown-file attack-path reconstruction.

The CDE pipeline already detects unknown files and upstream products can provide
rich context fields. Table names are only used to describe the origin of fields;
the agent can receive JSON/API/message inputs and does not need to query tables
directly.

This agent starts from those fields and answers:

- Did the unknown file only land on disk, or was it executed?
- What process chain led to it?
- Are there black, grey, or suspicious files in that chain?
- Are abnormal events close to this file/process/time?
- What initial attack path can be reconstructed?
- Is this likely to be a real attack?

## Current MVP Skills

### 1. database_event_normalizer

Implemented in `skills/normalizer.py`.

Inputs:

- One `T_FILE_DETAILS`-like record
- Optional `T_PROCESS_CHAIN_HASH` rows
- Optional `T_abnormal_event_TO_REPORT_OS` rows or equivalent event JSON

Responsibilities:

- Normalize file metadata.
- Normalize host, asset, pod, and container fields.
- Normalize trigger process fields.
- Parse `DETAIL.context`.
- Flatten `DETAIL.context[].tree` into a process chain.
- Enrich process-chain nodes with hash reputation.
- Normalize abnormal events.

### 2. process_chain_analyzer

Implemented in `skills/process_chain_analyzer.py`.

Responsibilities:

- Detect whether the process chain is traceable.
- Detect process-start discovery via `REALTIME_TYPE=1`.
- Detect root execution via `EUID=0`.
- Detect SSH shell execution patterns.
- Detect web-process, shell, downloader, and persistence parents.
- Detect risky hash reputation in `T_PROCESS_CHAIN_HASH`.

### 3. abnormal_event_correlator

Implemented in `skills/abnormal_event_correlator.py`.

Responsibilities:

- Convert abnormal event records into evidence.
- Preserve network IP/port and attack-phase fields.
- Attach abnormal events to the unknown-file case.

### 4. attack_path_reconstructor

Implemented in `skills/attack_path.py`.

Responsibilities:

- Convert evidence into ordered attack steps.
- Assign a simple phase label to each evidence type.

### 5. verdict_generator

Implemented in `skills/verdict.py`.

Responsibilities:

- Score evidence.
- Generate a first-pass verdict.
- Produce reasons and recommended actions.

## Next Skills

These are not implemented yet:

- `sample_loader_and_static_analyzer`: load HOFS sample and analyze ELF/script body.
- `script_parser_adapter`: adapt the company-provided script parsing skill.
- `linux_persistence_analyzer`: correlate cron/systemd/SSH key/SUID/LD_PRELOAD with the unknown file.
- `defense_evasion_adapter`: adapt the company-provided defense-evasion skill.
- `network_behavior_correlator`: correlate network logs or pcap summaries with PID/process/time.
