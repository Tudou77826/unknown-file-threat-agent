# Linux Unknown-File Threat Agent V1

An evidence-grounded investigation agent for Linux unknown-file alerts. V1 focuses on a complete backdoor/C2 investigation loop and includes benign and insufficient-evidence counterexamples.

## What V1 Implements

- PPT field aliases and millisecond timestamps
- `Detail` as JSON string or object
- `InitialCasePackage` semantics through `InvestigationState`
- Evidence, Claim, Fact, Finding, Relation, Hypothesis, EvidenceGap, Coverage and Scope
- Unified Evidence Tool and Analysis Tool registry
- Policy and investigation budgets
- Deterministic analyzers for execution, process chain, network, persistence and counter-evidence
- Framework-independent investigation loop
- Optional Deep Agents 0.7 planner adapter
- Attack-path relations and evidence references
- Closure/Verdict validation
- JSON and Markdown reports
- Malicious, benign and insufficient-evidence cases

## P0 Planning Safety Contract

- Four discriminated action schemas: `EvidenceRequest`, `AnalysisRequest`, `ScopeRequest`, and `FinishRequest`
- Non-empty objectives and action-specific required fields
- Dynamic, state-aware tool catalog generated from the registry
- Existing evidence IDs and eligible analyzer inputs exposed to the planner
- Deterministic validation of gap IDs, evidence references, tool capabilities, scope, and duplicate analysis
- At most one model repair attempt for a semantically invalid candidate action
- Deep Agents compatibility through a concrete Pydantic response wrapper; business code still receives a typed action variant

## P1.1 Investigation Closure Contract

- Evidence collection advances a gap to `evidence_collected`; it no longer marks the investigative question resolved
- Collected evidence deterministically creates typed `AnalysisObligation` records
- Required analysis obligations run before the LLM can choose another investigation branch
- Successful analyzers complete obligations and advance their related gaps to `resolved`
- Failed analyzers retain explicit limitations and leave the related gap partially resolved
- Finish requests are denied while required analysis is pending or a collected gap still needs analysis
- JSON reports expose every analysis obligation and its final status

## P1 Complete C2 Investigation Slice

P1 uses case-scoped raw events under `cases/<case>/events/*.jsonl`; the old answer-bearing `evidence.json` fixtures were removed.

### Investigation-level evidence tools

- `query_process_execution`: confirm execution of the investigated file
- `query_process_relations`: collect independently observed parent-child relations
- `query_child_process_execution`: collect commands executed by child processes
- `query_process_network`: collect process-attributed connections
- `query_socket_activity`: collect inbound and outbound socket activity
- `query_systemd_events`: collect unit writes, enablement and service starts
- `query_package_provenance`: collect file ownership and package-signature records
- `query_approved_endpoints`: collect CMDB/operations endpoint baselines
- Additional registered extension points cover login sessions, file activity, DNS and cron events

Every query supports case-scope enforcement and optional `host_id`, `entity_ids`, `start_time`, `end_time`, `filters`, and `limit` parameters. Repository results include requested and available time coverage plus truncation/data-source limitations.

### Deterministic C2 analysis

- Execution is derived from independent `process_exec` records.
- Process ancestry is reconstructed from `process_parent_relation` records.
- Periodic communication is calculated from connection timestamps.
- Remote command execution requires an ordered combination of inbound socket data, a child relation, a child command event and outbound socket data. No event contains a precomputed remote-command verdict.
- Active systemd persistence requires a unit write that references the file, followed by enable and start events.
- A benign explanation requires both trusted package provenance and an approved endpoint baseline.

### Acceptance cases

- `c2_malicious`: execution, verified ancestry, periodic C2, derived remote command execution, active systemd persistence and negative counter-evidence
- `c2_benign`: signed package, approved endpoint, normal periodic monitoring traffic and package-installed systemd service
- `insufficient_evidence`: execution evidence exists, but process ancestry and counter-evidence are partial while network and persistence sources are unavailable

Verdict validation rejects unresolved Fact/Finding evidence references and attack-path relations whose evidence or endpoint entities do not exist.

## P2.0 Investigation Foundation

P2 keeps deterministic security judgments outside the LLM while expanding the model's investigation-planning role.

- Analysis tools consume only the `evidence_refs` authorized by an `AnalysisRequest`; they no longer scan an entire state domain.
- Coverage separates source availability (`available_start/end`) from returned-event range (`result_start/end`) and records completeness.
- Completed analysis obligations record positive/negative outcomes, result references and limitations.
- Evidence gaps retain an explicit positive, negative, partial or unresolvable resolution.
- `EvidenceRole` describes what each hypothesis must prove; `Interpretation` is reserved for evidence-grounded LLM case explanations.
- Deep Agents decisions now identify the target Hypothesis, Evidence Role and Gap and include a concise decision summary.
- `PlannerDecision` records candidate tools, local repairs and fallbacks without storing hidden chain-of-thought.
- Verdicts separate supporting from contradicting references.
- Reports expose analysis notes and an explicit Verdict Validator PASS/FAIL result.
- Each output directory also contains `evaluation.json`; case expectations live in `cases/<case>/expected.json`.

The model may propose hypotheses, gaps and investigation choices, but it may not create confirmed Facts, deterministic Findings, evidence references, scope approvals or final validated verdicts.

## P2.1 File Provenance and Controlled Scenario Activation

- Analysis tools declare both their input evidence requirements and the specific `gap_type` they resolve. Input dependencies no longer receive unrelated analyzer limitations.
- `primary_gap_id` gives automatic analysis decisions an accurate target.
- The LLM may activate only reviewed scenarios from `activatable_scenarios`, with existing evidence/fact/finding references as justification.
- The `file_provenance` template adds a candidate Hypothesis, provenance Evidence Role and file-origin EvidenceGap locally.
- Evidence tools cover creation, download, remote transfer, archive extraction, package installation and web upload origins.
- `FileProvenanceAnalyzer` derives origin Facts and evidence-grounded Relations without treating delivery as malicious by itself.
- `requirement_mode=any` represents alternative origin evidence types without forcing every origin tool to run.
- Three P2.1 cases cover downloaded delivery, trusted package installation and unavailable file telemetry.

## P2.2 Data Exfiltration

- A reviewed `data_exfiltration` scenario adds separate Evidence Roles and Gaps for sensitive access, staging, egress and legitimate-transfer counter-evidence.
- Evidence tools query discovery commands, successful sensitive-file access, archive/staging activity, process-attributed byte transfers, HTTP uploads, DNS payloads and approved transfer baselines.
- Deterministic analyzers distinguish discovery, credential access, staging, volume, DNS tunneling and a confirmed end-to-end exfiltration chain.
- HTTPS confirmation requires the same process tree to read sensitive input, place it into a concrete archive, and transfer that exact archive to an unapproved destination in chronological order.
- DNS confirmation requires sensitive staging plus a process-attributed payload sequence meeting explicit count, uniqueness, length and entropy thresholds.
- An approved process-and-destination baseline produces `legitimate_backup_explanation`; it prevents a benign backup from being labelled as confirmed exfiltration.
- The Verdict Validator independently requires execution, sensitive access, staging, egress and baseline evidence before accepting a confirmed data-exfiltration verdict.
- Four comparison cases cover malicious HTTPS transfer, malicious DNS transfer, approved backup and unavailable evidence sources.

## P2.3 Ransomware Impact

- Evidence tools cover bulk modification metrics, content/header/entropy changes, rename patterns, backup and snapshot destruction, service disruption, ransom notes and authorized batch baselines.
- Probable encryption requires both content transformation and repeated extension changes; destructive commands count only when their outcome succeeded.
- Confirmed ransomware requires execution, broad high-rate impact, encryption-like transformation, destructive or ransom impact, and explicit counter-evidence review.
- Malicious, failed-attempt, authorized batch and unavailable-source cases prevent capability, command text and bulk maintenance from being treated as proven ransomware.

## P2.4 Controlled Cross-Host Investigation

- `ScopeExpansion` records candidate hosts, cited evidence, requested domains/window, approval status/source and limitations.
- Policy requires every candidate host to be named by cited Evidence, limits a request to three hosts, enforces domains/window and applies an independent expansion budget.
- The default policy is `approval_required`; fixture cases may explicitly use `automatic` to test the post-approval evidence loop.
- Cross-host tools cover hash presence, internal connections, remote logins, account use, file transfer, shared endpoints and asset/deployment context.
- Direct login + file transfer + matching hash + target execution supports lateral propagation. Shared C2 alone does not. Approved deployment is counter-evidence.

## P2.5 Auditable Orchestration and Convergence

- Every eligible tool receives an auditable `ToolScore` composed from gap priority, Evidence Role value, expected information gain, Coverage, counter-evidence value, query/scope cost, repeat penalty and repair priority.
- Every Evidence Tool response becomes an `EvidencePack` containing the request, target Gap/Role/Hypothesis, returned evidence IDs, Coverage, analysis obligations, outcome and limitations.
- Typed `RepairAction` objects represent invalid-action repair, alternative-source collection, incomplete analyzer inputs, verdict-support repair, denied scope and budget convergence.
- Verdict validation may reopen a relevant Gap and request an untried supporting tool, but repairs are bounded by independent repair budgets.
- The Deep Agents state view is sliced to relevant evidence, recent calls, recent Evidence Packs, pending repairs and the top-ranked tools; the complete state remains in the deterministic engine.
- Explicit ransomware, exfiltration and cross-host case profiles no longer force unrelated C2 gaps, while later evidence can still activate the reviewed C2 scenario.
- The Linux investigation Skill now includes source-specific checklists, alternative-source strategy, EvidencePack discipline and convergence rules derived from reviewed Linux forensic practices.
- P2.5 acceptance: 59 automated tests, all 18 deterministic comparison cases, and a complete GLM/DeepAgents ransomware run pass.

## Environment

All commands below are run from the project root:

```text
Anthropic-Cybersecurity-Skills-main/unknown-file-threat-agent
```

Create or synchronize the project-local virtual environment, including test dependencies:

```powershell
uv sync --extra dev
```

## Run Offline Deterministic Mode

```powershell
.\.venv\Scripts\python.exe -m threat_agent.cli `
  --case cases\c2_malicious `
  --mode deterministic `
  --output outputs\c2_malicious
```

Other cases:

```text
cases/c2_benign
cases/insufficient_evidence
cases/exfil_https_malicious
cases/exfil_dns_malicious
cases/exfil_benign_backup
cases/exfil_insufficient
cases/ransomware_malicious
cases/ransomware_partial_attempt
cases/ransomware_benign_batch
cases/ransomware_insufficient
cases/cross_host_malicious
cases/cross_host_benign_deployment
cases/cross_host_shared_c2_only
cases/cross_host_scope_denied
```

## Run Deep Agents Planner Mode

Deep Agents selects one structured investigation action per turn. Tool execution, policy, deterministic analysis and verdict validation remain in the business core.

Copy `.env.example` to `.env` and put your local credentials in `.env`. The
application loads this file automatically; `.env` is ignored by Git.

```powershell
Copy-Item .env.example .env
# Edit .env once and replace the placeholder API key.

.\.venv\Scripts\python.exe -m threat_agent.cli `
  --case cases\c2_malicious `
  --mode deepagents `
  --output outputs\c2_malicious_agent
```

Alternatively, edit the variables at the top of `run_case.sh`, then run it
from Git Bash or WSL:

```bash
bash run_case.sh
```

On Windows PowerShell, use the native equivalent:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_case.ps1
```

The selected LangChain model provider and its credentials must be installed/configured separately.

## Test

```powershell
.\.venv\Scripts\python.exe -m pytest
```

## Legacy Prototype

The pre-V1 prototype is isolated under `legacy_mvp/`. V1 does not import or execute it. Remove it only after V1 acceptance.
