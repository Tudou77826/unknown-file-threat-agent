# V1 Implementation Status

## Implemented

- Old prototype isolated under `legacy_mvp/`; V1 imports nothing from it.
- PPT fields from slides 14-16 supported, including aliases and millisecond timestamps.
- `Detail` supports JSON string and object forms; upstream `tree` order is preserved as direct-parent-to-root.
- Strict Pydantic models for Evidence, Claim, Fact, Finding, Relation, Hypothesis, EvidenceGap, Coverage, Scope, Budget and Verdict.
- Fixture Evidence Repository and a replaceable repository protocol.
- Unified Evidence/Analysis Tool Registry.
- Read-only Policy and iteration/tool-call budgets.
- Deterministic execution, process-chain, network, persistence and counter-evidence analyzers.
- Framework-independent investigation engine and deterministic planner.
- Deep Agents 0.7.1 planner adapter with structured `InvestigationAction` output.
- Deep Agents structured-output path smoke-tested with a controllable LangChain fake chat model: the framework parsed a model tool call into `InvestigationAction` successfully.
- Linux unknown-file investigation Skill loaded into the Deep Agents planner prompt.
- Hypothesis updates, relation-based attack path, evidence-grounded verdict validation.
- JSON/Markdown reporting.
- Malicious C2, benign counterexample and insufficient-evidence cases.
- End-to-end and ingestion tests.

## V1 conclusion gates

| Result | Minimum condition |
| --- | --- |
| `confirmed_malicious/backdoor_c2` | execution + active persistence + correlated remote command evidence |
| `likely_malicious/backdoor_c2` | execution + active persistence + periodic external communication |
| `suspicious/backdoor_c2` | execution + one suspicious runtime behavior |
| `benign` | trusted provenance/approved baseline and no direct malicious contradiction |
| `insufficient_evidence` | malicious chain cannot be proven, including unavailable data sources |

## Known V1 boundaries

- Evidence Repository is fixture-backed; production EDR/log adapters are not implemented.
- Cross-host ScopeRequest is policy controlled. The default requires explicit approval; an explicit `automatic` test policy exercises the post-approval loop.
- Deep Agents mode requires a configured LangChain model provider and credentials.
- OpenAI, Anthropic and Google LangChain providers are installed locally, but no corresponding API key was present during acceptance; no external-model result is claimed.
- Backdoor/C2, data-exfiltration and ransomware have deterministic closure rules and comparison cases; production data adapters remain outstanding.
- Container PID/host PID resolution and boot-ID based PID reuse protection require production telemetry.
- Report persistence can be blocked by restricted execution sandboxes; report serialization itself is deterministic.
