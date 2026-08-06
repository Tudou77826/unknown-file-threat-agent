from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import Any, Protocol

from pydantic import TypeAdapter

from .models import AnalysisRequest, EvidenceRequest, FinishRequest, InvestigationAction, InvestigationActionResponse, InvestigationState, PlannerDecision, ScopeRequest, ToolScore
from .scenarios import activate_scenario, activation_catalog, add_interpretation
from .tools import ToolRegistry


ACTION_ADAPTER = TypeAdapter(InvestigationAction)


class EmptyModelResponseError(RuntimeError):
    """Raised after the model repeatedly completes without response content."""


class Planner(Protocol):
    def plan(self, state: InvestigationState) -> InvestigationAction: ...


class DeterministicPlanner:
    """Repeatable investigation policy used by tests and offline demonstrations."""

    sequence = [
        ("evidence_request", "query_process_execution", "gap-execution", "Collect independent process execution events"),
        ("evidence_request", "query_file_origin", "gap-file-origin", "Collect independent creation or delivery events for the investigated file"),
        ("analysis_request", "analyze_execution", "process_exec", "Verify whether the unknown file actually executed"),
        ("evidence_request", "query_process_relations", "gap-process-chain", "Collect independent parent-child process relations"),
        ("analysis_request", "analyze_process_chain", "process_parent_relation", "Verify independent parent-child process relations"),
        ("evidence_request", "query_process_network", "gap-network", "Collect process-attributed network connection events"),
        ("analysis_request", "analyze_network", "network_connection", "Identify external periodic or remote-command behavior"),
        ("evidence_request", "query_socket_activity", "gap-remote-command", "Collect process-attributed socket input and output events"),
        ("evidence_request", "query_child_process_execution", "gap-remote-command", "Collect commands executed by child processes"),
        ("analysis_request", "analyze_remote_command", "socket_io", "Correlate inbound data, child commands and outbound results"),
        ("evidence_request", "query_systemd_events", "gap-persistence", "Collect raw systemd unit write, enable and start events"),
        ("analysis_request", "analyze_persistence", "systemd_event", "Determine whether systemd persistence references the unknown file"),
        ("evidence_request", "query_package_provenance", "gap-counter", "Collect package ownership and signature provenance"),
        ("evidence_request", "query_approved_endpoints", "gap-counter", "Collect approved endpoint and operations baseline evidence"),
        ("analysis_request", "analyze_reputation", "package_provenance", "Evaluate legitimate software and operational explanations"),
        ("evidence_request", "query_discovery_commands", "gap-sensitive-discovery", "Collect process-attributed sensitive-data discovery commands"),
        ("evidence_request", "query_sensitive_file_access", "gap-sensitive-access", "Collect successful reads of credentials and sensitive files"),
        ("evidence_request", "query_archive_activity", "gap-data-staging", "Collect archive creation and sensitive archive membership evidence"),
        ("evidence_request", "query_data_transfer", "gap-data-transfer", "Collect process-attributed outbound transfer and upload evidence"),
        ("evidence_request", "query_dns_payload_activity", "gap-dns-tunnel", "Collect process-attributed DNS payload activity"),
        ("evidence_request", "query_data_transfer_baseline", "gap-transfer-counter", "Collect approved process and destination transfer baselines"),
        ("evidence_request", "query_bulk_file_modification", "gap-bulk-file-impact", "Collect file modification rate and impact breadth metrics"),
        ("evidence_request", "query_file_content_change", "gap-file-encryption", "Collect entropy, header and content transformation metrics"),
        ("evidence_request", "query_file_rename_patterns", "gap-file-encryption", "Collect repeated rename and extension patterns"),
        ("evidence_request", "query_backup_destruction", "gap-recovery-inhibition", "Collect backup destruction outcomes"),
        ("evidence_request", "query_snapshot_activity", "gap-recovery-inhibition", "Collect snapshot deletion outcomes"),
        ("evidence_request", "query_destructive_commands", "gap-recovery-inhibition", "Collect destructive commands and their outcomes"),
        ("evidence_request", "query_service_disruption", "gap-service-disruption", "Collect actual service disruption outcomes"),
        ("evidence_request", "query_ransom_note_activity", "gap-ransom-note", "Collect ransom-note creation evidence"),
        ("evidence_request", "query_ransomware_baseline", "gap-ransomware-counter", "Collect approved batch-processing counter-evidence"),
        ("evidence_request", "query_file_transfer_across_hosts", "gap-cross-host-lead", "Collect direct source-to-target file transfer evidence"),
        ("evidence_request", "query_internal_connections", "gap-cross-host-lead", "Collect internal connections that identify related hosts"),
        ("evidence_request", "query_shared_endpoint_hosts", "gap-cross-host-lead", "Collect hosts sharing the same external endpoint"),
        ("evidence_request", "query_hash_presence", "gap-cross-host-confirmation", "Confirm the investigated hash on approved scoped hosts"),
        ("evidence_request", "query_remote_login_sessions", "gap-cross-host-confirmation", "Collect related remote login sessions between scoped hosts"),
        ("evidence_request", "query_host_asset_context", "gap-cross-host-counter", "Collect approved deployment and asset-role counter-evidence"),
    ]
    analysis_requirements = {
        "analyze_execution": {"process_exec"},
        "analyze_process_chain": {"process_parent_relation"},
        "analyze_network": {"network_connection"},
        "analyze_remote_command": {"network_connection", "socket_io", "child_process_exec", "process_parent_relation"},
        "analyze_persistence": {"systemd_event"},
        "analyze_reputation": {"package_provenance", "approved_endpoint"},
        "analyze_sensitive_discovery": {"discovery_command"},
        "analyze_credential_access": {"sensitive_file_access"},
        "analyze_data_staging": {"archive_create", "archive_member"},
        "analyze_data_transfer": {"network_transfer", "http_upload"},
        "analyze_dns_tunneling": {"dns_query"},
        "analyze_https_exfiltration": {"sensitive_file_access", "archive_create", "archive_member", "network_transfer", "transfer_baseline"},
        "analyze_dns_exfiltration": {"sensitive_file_access", "archive_create", "archive_member", "dns_query", "transfer_baseline"},
        "analyze_bulk_file_impact": {"bulk_file_metric"},
        "analyze_probable_file_encryption": {"file_content_change", "file_rename_pattern"},
        "analyze_recovery_inhibition": {"backup_destruction", "snapshot_activity", "destructive_command"},
        "analyze_ransom_note": {"ransom_note"},
        "analyze_service_disruption": {"service_disruption"},
        "analyze_ransomware_chain": {"bulk_file_metric", "file_content_change", "file_rename_pattern", "backup_destruction", "snapshot_activity", "ransom_note", "authorized_batch_baseline"},
        "analyze_cross_host_path": {"file_transfer_cross_host", "hash_presence", "remote_login_session", "host_asset_context"},
        "analyze_cross_host_lead": {"file_transfer_cross_host", "internal_connection", "shared_endpoint_host"},
    }

    def plan(self, state: InvestigationState) -> InvestigationAction:
        pending = next(
            (item for item in state.analysis_obligations if item.required_for_closure and item.status == "pending"),
            None,
        )
        if pending is not None:
            return AnalysisRequest(
                tool_name=pending.tool_name,
                objective=f"Complete required analysis obligation {pending.obligation_id}",
                evidence_refs=pending.evidence_refs,
            )
        if "cross_host" in state.active_scenarios:
            requested_before = {host for item in state.scope_expansions for host in item.candidate_host_ids}
            for evidence in state.evidence:
                if evidence.evidence_type != "file_transfer_cross_host" or not evidence.data.get("success"):
                    continue
                target = str(evidence.data.get("target_host_id") or "")
                if target and target not in state.scope.host_ids and target not in requested_before:
                    return ScopeRequest(
                        objective="Expand investigation to the directly evidenced file-transfer target host",
                        requested_host_ids=[target],
                        reason_evidence_refs=[evidence.evidence_id],
                        reason_type="file_transfer",
                        requested_domains=["process", "file", "network", "reputation"],
                        start_time=state.scope.start_time,
                        end_time=state.scope.end_time,
                    )
        # A denied/error action is still an attempted action. Repeating it forever
        # cannot change Policy or the data source and would only exhaust the budget.
        called = {x.tool_name for x in state.tool_calls}
        known_gaps = {gap.gap_id for gap in state.evidence_gaps}
        gaps_by_id = {gap.gap_id: gap for gap in state.evidence_gaps}
        for action_type, tool, reference, objective in self.sequence:
            if tool not in called:
                if action_type == "evidence_request":
                    if reference not in known_gaps:
                        continue
                    if gaps_by_id[reference].status in {"resolved", "unresolvable"}:
                        continue
                    return EvidenceRequest(tool_name=tool, gap_id=reference, objective=objective)
                required_types = self.analysis_requirements[tool]
                refs = [e.evidence_id for e in state.evidence if e.evidence_type in required_types]
                present_types = {e.evidence_type for e in state.evidence if e.evidence_type in required_types}
                if refs and required_types <= present_types:
                    return AnalysisRequest(tool_name=tool, objective=objective, evidence_refs=refs)
        resolved = [g.gap_id for g in state.evidence_gaps if g.status == "resolved"]
        unresolved = [g.gap_id for g in state.evidence_gaps if g.status != "resolved"]
        return FinishRequest(
            objective="All mandatory evidence domains and available analyses have been attempted",
            resolved_gap_ids=resolved,
            unresolved_gap_ids=unresolved,
        )


def state_view(state: InvestigationState, registry: ToolRegistry) -> str:
    catalog = registry.catalog(state)
    open_types = {
        evidence_type
        for gap in state.evidence_gaps
        if gap.status not in {"resolved", "unresolvable"}
        for evidence_type in gap.required_evidence_types
    }
    cited_refs = {
        ref for item in [*state.facts, *state.findings] for ref in item.evidence_refs
    }
    relevant_evidence = [
        item for item in state.evidence
        if item.evidence_type in open_types or item.evidence_id in cited_refs
    ][-60:]
    payload = {
        "case_id": state.case_id,
        "entities": [e.model_dump(mode="json") for e in state.entities],
        "claims": [c.model_dump(mode="json") for c in state.claims],
        "evidence": [
            {
                "evidence_id": e.evidence_id,
                "evidence_type": e.evidence_type,
                "domain": e.domain,
                "observed_at": e.observed_at.isoformat() if e.observed_at else None,
                "subject_refs": e.subject_refs,
                "status": e.status.value,
                "summary": e.data,
                "limitations": e.limitations,
            }
            for e in relevant_evidence
        ],
        "facts": [f.model_dump(mode="json") for f in state.facts],
        "findings": [f.model_dump(mode="json") for f in state.findings],
        "hypotheses": [h.model_dump(mode="json") for h in state.hypotheses],
        "evidence_roles": [role.model_dump(mode="json") for role in state.evidence_roles],
        "interpretations": [item.model_dump(mode="json") for item in state.interpretations],
        "evidence_gaps": [g.model_dump(mode="json") for g in state.evidence_gaps],
        "analysis_obligations": [item.model_dump(mode="json") for item in state.analysis_obligations],
        "coverage": {k: v.model_dump(mode="json") for k, v in state.coverage.items()},
        "recent_tool_calls": [
            {"tool_name": t.tool_name, "status": t.status, "objective": t.objective, "error": t.error}
            for t in state.tool_calls[-20:]
        ],
        "recent_evidence_packs": [item.model_dump(mode="json") for item in state.evidence_packs[-8:]],
        "pending_repair_actions": [item.model_dump(mode="json") for item in state.repair_actions if item.status == "pending"],
        "recent_planner_decisions": [item.model_dump(mode="json") for item in state.planner_decisions[-5:]],
        "budget": state.budget.model_dump(),
        "available_tool_catalog": catalog[:12],
        "omitted_lower_scored_tools": max(0, len(catalog) - 12),
        "activatable_scenarios": activation_catalog(state),
    }
    return json.dumps(payload, ensure_ascii=False)


class DeepAgentsPlanner:
    """Use Deep Agents only for semantic next-action selection; execution remains policy-controlled."""

    def __init__(self, model: Any, registry: ToolRegistry):
        from deepagents import (
            GeneralPurposeSubagentProfile,
            HarnessProfileConfig,
            create_deep_agent,
            register_harness_profile,
        )

        profile_key = model.model_name

        skill_path = Path(__file__).resolve().parents[1] / "investigation_skills" / "linux-unknown-file" / "SKILL.md"
        skill = skill_path.read_text(encoding="utf-8") if skill_path.exists() else ""
        prompt = """You are a Linux unknown-file threat investigation planner. Choose exactly one tool_name from the dynamically supplied available_tool_catalog.
Return one JSON object with tool_name, target_hypothesis_id, target_evidence_role_id, target_gap_id, a concise decision_summary, optional activate_scenarios, optional interpretation, and optional scope_request.
Example: {"tool_name":"query_process_execution","target_hypothesis_id":"hyp-c2-001","target_evidence_role_id":"role-execution","target_gap_id":"gap-execution","decision_summary":"Independent process telemetry is required before runtime behavior can be attributed.","activate_scenarios":[{"scenario":"file_provenance","reason_refs":["ev-input-file-001"]}]}
Only activate scenarios listed in activatable_scenarios, and every reason_refs item must already exist in Evidence, Fact, or Finding. Activation selects a reviewed local template; it does not authorize creating arbitrary Facts, Findings, rules, or tools.
An interpretation may explain existing Facts/Findings but must cite them using supporting_fact_refs, supporting_finding_refs and contradicting_refs. It remains a candidate interpretation and never becomes a Fact or deterministic Finding.
If the catalog is empty or the investigation should finish, set tool_name to "__finish__".
To propose a controlled host expansion, set tool_name to "__scope__" and include scope_request with requested_host_ids, reason_type, reason_evidence_refs and requested_domains. Every candidate host must be explicitly named by the cited existing evidence; the local Policy decides approval.
Never return objective, evidence_refs, parameters, nested action objects, Markdown, Fact, Finding, or Verdict. Local deterministic code constructs and validates the full action.
Prefer the highest-priority evidence gap, check benign alternatives, and request finish only after mandatory domains were attempted.
Tool scores are deterministic advisory rankings. Prefer higher-scored tools unless the cited case semantics justify another eligible choice. Never select an omitted or ineligible tool.
Treat pending_repair_actions as explicit investigation feedback: address a blocking repair before unrelated optional work. Use recent Evidence Packs to avoid duplicate queries and to distinguish a complete negative result from incomplete Coverage.
When a scenario profile is explicit, do not investigate unrelated scenario branches unless existing Evidence, Fact or Finding justifies activating that reviewed scenario.
Before finish, use an optional Interpretation to compare supported and legitimate hypotheses with resolvable Fact/Finding references. Interpretation never overrides deterministic Findings or Validator gates.
The JSON state is the complete planning input. Paths such as /tmp/.cache/sysupd are evidence values from the investigated Linux host, not files in your runtime. Do not inspect, list, read, write, grep, or execute any path.
Do not expand scope in V1 unless evidence explicitly points to another host.
""" + "\n\nInvestigation skill:\n" + skill
        # V1 intentionally uses one main investigation agent. Disable the
        # framework's otherwise automatic general-purpose subagent.
        single_agent_profile = HarnessProfileConfig(
            general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False),
            excluded_tools=frozenset(
                {
                    "ls",
                    "read_file",
                    "write_file",
                    "edit_file",
                    "delete",
                    "glob",
                    "grep",
                    "execute",
                    "task",
                }
            ),
        )
        register_harness_profile(profile_key, single_agent_profile)
        register_harness_profile(f"openai:{profile_key}", single_agent_profile)
        self.registry = registry
        self.model_name = str(model.model_name)
        # Some OpenAI-compatible models emit the structured-response tool more
        # than once in a single turn. Stream one JSON object as ordinary text
        # and validate it locally instead of relying on ToolStrategy.
        self.graph = create_deep_agent(model=model, tools=[], system_prompt=prompt, subagents=[])

    def plan(self, state: InvestigationState) -> InvestigationAction:
        pending = next(
            (item for item in state.analysis_obligations if item.required_for_closure and item.status == "pending"),
            None,
        )
        if pending is not None:
            state.planner_decisions.append(PlannerDecision(
                decision_id=f"decision-{uuid.uuid4().hex[:10]}",
                iteration=state.budget.iterations_used,
                decision_type="analyze",
                selected_tool=pending.tool_name,
                target_gap_id=pending.primary_gap_id,
                decision_summary=f"Deterministic analysis obligation {pending.obligation_id} must be completed before further planning.",
                candidate_tools=[pending.tool_name],
                planner_mode="automatic",
            ))
            return AnalysisRequest(
                tool_name=pending.tool_name,
                objective=f"Complete required analysis obligation {pending.obligation_id}",
                evidence_refs=pending.evidence_refs,
            )
        catalog = self.registry.catalog(state)
        state.tool_scores.extend(
            ToolScore.model_validate(item["score_breakdown"])
            for item in catalog
            if not any(existing.iteration == state.budget.iterations_used and existing.tool_name == item["tool_name"] for existing in state.tool_scores)
        )
        has_scope_candidate = any(
            evidence.evidence_type == "file_transfer_cross_host"
            and evidence.data.get("success")
            and evidence.data.get("target_host_id") not in state.scope.host_ids
            and not any(evidence.data.get("target_host_id") in item.candidate_host_ids for item in state.scope_expansions)
            for evidence in state.evidence
        )
        if not catalog and not has_scope_candidate:
            state.planner_decisions.append(PlannerDecision(
                decision_id=f"decision-{uuid.uuid4().hex[:10]}", iteration=state.budget.iterations_used,
                decision_type="finish", decision_summary="No eligible investigation or analysis tool remains after mandatory gaps were accounted for.",
                candidate_tools=[], planner_mode="automatic",
            ))
            return self._finish_action(state)
        fallback_used = False
        try:
            proposal = self._generate("Select the next investigation decision for this state:\n" + state_view(state, self.registry))
            tool_name = proposal["tool_name"]
        except EmptyModelResponseError:
            tool_name = catalog[0]["tool_name"]
            proposal = {"tool_name": tool_name, "decision_summary": "The model returned no usable response; the highest-ranked eligible catalog tool was selected."}
            fallback_used = True
            print(
                f"[DeepAgents] empty response fallback: {tool_name}",
                flush=True,
            )
        activated_scenarios = []
        activation_repaired = False
        for activation in proposal.get("activate_scenarios") or []:
            try:
                if activate_scenario(
                    state,
                    str(activation.get("scenario", "")),
                    [str(ref) for ref in activation.get("reason_refs") or []],
                ):
                    activated_scenarios.append(str(activation["scenario"]))
            except (TypeError, ValueError):
                activation_repaired = True
        if activated_scenarios:
            catalog = self.registry.catalog(state)
        created_interpretation_id = None
        interpretation_repaired = False
        if proposal.get("interpretation"):
            try:
                created_interpretation_id = add_interpretation(
                    state,
                    proposal["interpretation"],
                    getattr(self, "model_name", "unknown"),
                )
            except (TypeError, ValueError):
                interpretation_repaired = True
        choices = {item["tool_name"]: item for item in catalog}
        if tool_name == "__scope__":
            scope = proposal.get("scope_request") or {}
            evidence_ids = {item.evidence_id for item in state.evidence}
            proposed_refs = [str(item) for item in scope.get("reason_evidence_refs") or []]
            normalized_refs = [item for item in proposed_refs if item in evidence_ids]
            domain_aliases = {"host_asset": "reputation", "auth": "process", "authentication": "process"}
            proposed_domains = [domain_aliases.get(str(item), str(item)) for item in scope.get("requested_domains") or ["process", "file", "network"]]
            normalized_domains = list(dict.fromkeys(item for item in proposed_domains if item in state.scope.allowed_domains))
            scope_repaired = normalized_refs != proposed_refs or normalized_domains != list(scope.get("requested_domains") or ["process", "file", "network"])
            action = ScopeRequest(
                objective=str(proposal.get("decision_summary") or "Request evidence-grounded cross-host investigation scope"),
                requested_host_ids=[str(item) for item in scope.get("requested_host_ids") or []],
                reason_evidence_refs=normalized_refs,
                reason_type=str(scope.get("reason_type") or "related_host_evidence"),
                requested_domains=normalized_domains,
                start_time=state.scope.start_time,
                end_time=state.scope.end_time,
            )
            state.planner_decisions.append(PlannerDecision(
                decision_id=f"decision-{uuid.uuid4().hex[:10]}", iteration=state.budget.iterations_used,
                decision_type="scope", selected_tool=None,
                target_hypothesis_id=proposal.get("target_hypothesis_id"),
                target_evidence_role_id=proposal.get("target_evidence_role_id"),
                target_gap_id=proposal.get("target_gap_id"),
                decision_summary=str(proposal.get("decision_summary") or "Request controlled scope expansion"),
                candidate_tools=[item["tool_name"] for item in catalog], planner_mode="deepagents", repaired=scope_repaired,
            ))
            return action
        selected = choices.get(tool_name)
        actual_gap = selected["compatible_gap_ids"][0] if selected and selected["kind"] == "evidence" and selected["compatible_gap_ids"] else None
        hypothesis_ids = {item.hypothesis_id for item in state.hypotheses}
        role_ids = {item.role_id for item in state.evidence_roles}
        proposed_hypothesis = proposal.get("target_hypothesis_id")
        proposed_role = proposal.get("target_evidence_role_id")
        proposed_gap = proposal.get("target_gap_id")
        repaired = activation_repaired or interpretation_repaired or bool(
            (proposed_hypothesis and proposed_hypothesis not in hypothesis_ids)
            or (proposed_role and proposed_role not in role_ids)
            or (proposed_gap and proposed_gap != actual_gap)
        )
        state.planner_decisions.append(PlannerDecision(
            decision_id=f"decision-{uuid.uuid4().hex[:10]}",
            iteration=state.budget.iterations_used,
            decision_type="finish" if tool_name == "__finish__" else "investigate",
            selected_tool=tool_name,
            target_hypothesis_id=proposed_hypothesis if proposed_hypothesis in hypothesis_ids else None,
            target_evidence_role_id=proposed_role if proposed_role in role_ids else None,
            target_gap_id=actual_gap,
            decision_summary=str(proposal.get("decision_summary") or f"Selected eligible evidence tool {tool_name}."),
            candidate_tools=[item["tool_name"] for item in catalog],
            activated_scenarios=activated_scenarios,
            created_interpretation_id=created_interpretation_id,
            planner_mode="deepagents",
            repaired=repaired,
            fallback_used=fallback_used,
        ))
        return self._build_action(state, catalog, tool_name)

    def repair(self, state: InvestigationState, invalid_action: InvestigationAction, validation_error: str) -> InvestigationAction:
        return self.plan(state)

    @staticmethod
    def _finish_action(state: InvestigationState) -> FinishRequest:
        resolved = [gap.gap_id for gap in state.evidence_gaps if gap.status == "resolved"]
        unresolved = [gap.gap_id for gap in state.evidence_gaps if gap.status != "resolved"]
        return FinishRequest(
            objective="Finish after all currently eligible investigation actions were attempted",
            resolved_gap_ids=resolved,
            unresolved_gap_ids=unresolved,
        )

    def _build_action(self, state: InvestigationState, catalog: list[dict[str, Any]], tool_name: str) -> InvestigationAction:
        if tool_name == "__finish__":
            return self._finish_action(state)
        choices = {item["tool_name"]: item for item in catalog}
        if tool_name not in choices:
            raise RuntimeError(f"Model selected unavailable tool_name: {tool_name!r}")
        selected = choices[tool_name]
        if selected["kind"] == "evidence":
            return EvidenceRequest(
                tool_name=tool_name,
                objective=f"Collect scoped evidence with {tool_name}",
                gap_id=selected["compatible_gap_ids"][0],
            )
        return AnalysisRequest(
            tool_name=tool_name,
            objective=f"Run deterministic analysis with {tool_name}",
            evidence_refs=selected["eligible_evidence_refs"],
        )

    def _generate(self, instruction: str, attempt: int = 1, max_attempts: int = 3) -> dict[str, Any]:
        graph_input = {
            "messages": [
                {
                    "role": "user",
                    "content": instruction,
                }
            ]
        }
        structured: Any = None
        response_parts: list[str] = []
        reasoning_started = False
        answer_started = False
        response_chars_printed = 0
        response_preview_limit = 1200
        response_suppressed = False

        print("\n[DeepAgents] selecting next action...", flush=True)
        events = self.graph.stream(
            graph_input,
            stream_mode=["messages", "values"],
            subgraphs=True,
            version="v2",
        )
        while True:
            try:
                event = next(events)
            except StopIteration:
                break
            except IndexError as exc:
                raise RuntimeError(
                    "The model provider returned an empty or malformed generation. "
                    "Verify that MODEL_NAME supports chat streaming, tool calling, "
                    "and structured output."
                ) from exc

            event_type = event.get("type")
            data = event.get("data")

            if event_type == "messages":
                message, _metadata = data
                extra = getattr(message, "additional_kwargs", {}) or {}
                reasoning = extra.get("reasoning_content")
                if reasoning:
                    if not reasoning_started:
                        print("[reasoning] ", end="", flush=True)
                        reasoning_started = True
                    print(reasoning, end="", flush=True)

                content = getattr(message, "content", "")
                if isinstance(content, str) and content:
                    response_parts.append(content)
                    if reasoning_started and not answer_started:
                        print("\n", flush=True)
                    if not answer_started:
                        print("[response] ", end="", flush=True)
                        answer_started = True
                    remaining = response_preview_limit - response_chars_printed
                    if remaining > 0:
                        preview = content[:remaining]
                        print(preview, end="", flush=True)
                        response_chars_printed += len(preview)
                    if len(content) > remaining and not response_suppressed:
                        print("\n[response truncated; waiting for completion]", end="", flush=True)
                        response_suppressed = True

            elif event_type == "values" and isinstance(data, dict):
                candidate = data.get("structured_response")
                if candidate is not None:
                    structured = candidate

        if reasoning_started or answer_started:
            print(file=sys.stdout, flush=True)
        if structured is None:
            raw_response = "".join(response_parts).strip()
            if not raw_response:
                if attempt < max_attempts:
                    print(
                        f"[DeepAgents] empty response; retrying ({attempt + 1}/{max_attempts})...",
                        flush=True,
                    )
                    return self._generate(instruction, attempt + 1, max_attempts)
                raise EmptyModelResponseError(
                    f"DeepAgents returned an empty response {max_attempts} consecutive times"
                )
            if raw_response.startswith("```"):
                raw_response = raw_response.removeprefix("```json").removeprefix("```")
                raw_response = raw_response.removesuffix("```").strip()
            object_start = raw_response.find("{")
            object_end = raw_response.rfind("}")
            if object_start < 0 or object_end < object_start:
                raise RuntimeError(
                    "DeepAgents returned no JSON action. Raw model response: "
                    + raw_response[:500]
                )
            structured = json.loads(raw_response[object_start : object_end + 1])
        allowed_keys = {"tool_name", "target_hypothesis_id", "target_evidence_role_id", "target_gap_id", "decision_summary", "activate_scenarios", "interpretation", "scope_request"}
        if not isinstance(structured, dict) or "tool_name" not in structured or set(structured) - allowed_keys:
            raise RuntimeError(f"Expected one structured planner decision, got: {structured!r}")
        tool_name = structured["tool_name"]
        if not isinstance(tool_name, str) or not tool_name:
            raise RuntimeError(f"Invalid tool_name selection: {tool_name!r}")
        summary = structured.get("decision_summary")
        if summary is not None and (not isinstance(summary, str) or len(summary.strip()) < 10):
            raise RuntimeError(f"Invalid decision_summary: {summary!r}")
        activations = structured.get("activate_scenarios", [])
        if not isinstance(activations, list) or any(not isinstance(item, dict) for item in activations):
            raise RuntimeError(f"Invalid activate_scenarios: {activations!r}")
        interpretation = structured.get("interpretation")
        if interpretation is not None and not isinstance(interpretation, dict):
            raise RuntimeError(f"Invalid interpretation: {interpretation!r}")
        scope_request = structured.get("scope_request")
        if scope_request is not None and not isinstance(scope_request, dict):
            raise RuntimeError(f"Invalid scope_request: {scope_request!r}")
        if tool_name == "__scope__" and not scope_request:
            raise RuntimeError("__scope__ requires a non-empty scope_request")
        return structured
