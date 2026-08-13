from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Callable, Protocol

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from pydantic import Field, TypeAdapter

from ..domain.models import (
    AnalysisRequest,
    EvidenceRequest,
    FinishRequest,
    InvestigationAction,
    InvestigationState,
    PlannerDecision,
    ScenarioActivationRequest,
    ScopeRequest,
    StrictModel,
    ToolScore,
)
from ..domain.scenarios import activation_catalog
from ..adapters.tools import ToolRegistry
from .native_tool_calling import build_native_tools, parse_tool_call, serialize_messages


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


class StructuredJudgmentPlanner:
    """Native function-calling planner for the evidence/analysis path.

    The model picks one of the fixed native tools each turn; Policy
    (:func:`validate_action`) remains the guardrail for every produced action.
    """

    domain_tool_names = (
        "query_process_evidence",
        "query_file_evidence",
        "query_network_evidence",
        "query_persistence_evidence",
        "query_reputation_evidence",
    )

    def __init__(self, model: Any, registry: ToolRegistry, event_sink: Callable | None = None):
        skill_path = Path(__file__).resolve().parents[4] / "investigation_skills" / "linux-unknown-file" / "SKILL.md"
        skill = skill_path.read_text(encoding="utf-8") if skill_path.exists() else ""
        self.registry = registry
        self.model_name = str(getattr(model, "model_name", getattr(model, "model", "unknown")))
        self.event_sink = event_sink or (lambda _kind, _message, _details=None: None)
        self.system_prompt = (
            "你是 Linux 未知文件威胁调查的取证规划器。每轮只调用一个已注册工具，工具参数必须严格遵循其 JSON Schema。"
            "gap_id 必须从当前可用缺口列表中选择；evidence_refs 必须从当前待处理分析义务中选择。"
            "查询参数（host_id / entity_ids / start_time / end_time / limit）由你根据调查需要自由填写。"
            "空结果只表示该查询在执行边界内返回零条，不能据此断言行为没有发生。"
            "激活场景只能选择 activatable_scenarios 中列出的场景，且必须引用已存在的证据/事实/发现。"
            "候选关系只能用于继续调查，不能当作已确认事实。"
            "当进一步查询没有信息增益、或必须完成的分析义务已完成时，调用 finish_investigation。"
            "所有自然语言字段用简体中文。"
            "\n\nInvestigation skill:\n" + skill
        )
        self.tools = build_native_tools(self.registry.native_tool_specs())
        self.bound_model = model.bind_tools(
            self.tools,
            tool_choice="required",
            strict=True,
            parallel_tool_calls=False,
            extra_body={"thinking": {"type": "disabled"}},
        )

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
        if not self._can_act(state):
            state.planner_decisions.append(PlannerDecision(
                decision_id=f"decision-{uuid.uuid4().hex[:10]}", iteration=state.budget.iterations_used,
                decision_type="finish", decision_summary="No eligible investigation action remains.",
                candidate_tools=[], planner_mode="automatic",
            ))
            return self._finish_action(state)
        messages = self._messages(state)
        self.event_sink("model_input", "研判模型输入", {
            "phase": "judgment_planning",
            "iteration": state.budget.iterations_used,
            "messages": serialize_messages(messages),
            "registered_tools": [
                {"name": tool.name, "parameters": tool.args_schema.model_json_schema()}
                for tool in self.tools
            ],
        })
        response = self.bound_model.invoke(messages)
        if not isinstance(response, AIMessage):
            response = AIMessage(content=getattr(response, "content", str(response)))
        self.event_sink("model_output", "研判模型输出", {
            "phase": "judgment_planning",
            "iteration": state.budget.iterations_used,
            "content": response.content,
            "tool_calls": response.tool_calls,
        })
        if not response.tool_calls:
            state.planner_decisions.append(PlannerDecision(
                decision_id=f"decision-{uuid.uuid4().hex[:10]}",
                iteration=state.budget.iterations_used,
                decision_type="finish",
                decision_summary="The model issued no tool call; using current results to finalize.",
                candidate_tools=[],
                planner_mode="deepagents",
                fallback_used=True,
            ))
            return self._finish_action(state)
        name, args, call_id = parse_tool_call(response)
        action = self._map_action(state, name, args, call_id)
        self._record_decision(state, name, args)
        return action

    def _record_decision(self, state: InvestigationState, name: str, args: dict[str, Any]) -> None:
        decision_type = {
            "finish_investigation": "finish",
            "request_scope_expansion": "scope",
            "analyze_evidence": "analyze",
        }.get(name, "investigate")
        if name == "activate_scenario":
            summary = f"Activate reviewed scenario {args.get('scenario', '')} grounded in cited evidence."
        elif name == "analyze_evidence":
            summary = f"Run deterministic analysis on {len(args.get('evidence_refs') or [])} evidence references."
        elif name in self.domain_tool_names:
            summary = f"Collect {name} evidence for gap {args.get('gap_id', '')}."
        elif name == "finish_investigation":
            summary = str(args.get("objective") or "Finalize the investigation.")
        else:
            summary = str(args.get("objective") or f"Call tool {name}.")
        state.planner_decisions.append(PlannerDecision(
            decision_id=f"decision-{uuid.uuid4().hex[:10]}",
            iteration=state.budget.iterations_used,
            decision_type=decision_type,
            selected_tool=name,
            target_gap_id=args.get("gap_id") if name in self.domain_tool_names else None,
            decision_summary=summary,
            candidate_tools=[tool.name for tool in self.tools],
            activated_scenarios=[str(args["scenario"])] if name == "activate_scenario" else [],
            planner_mode="deepagents",
        ))

    def repair(self, state: InvestigationState, invalid_action: InvestigationAction, validation_error: str) -> InvestigationAction:
        self.event_sink("tool_message", "工具调用校验失败", {
            "phase": "judgment_planning",
            "tool_name": getattr(invalid_action, "tool_name", None),
            "error": validation_error,
        })
        return self.plan(state)

    def _can_act(self, state: InvestigationState) -> bool:
        if any(item.status == "pending" for item in state.analysis_obligations):
            return True
        if any(self.registry.eligible_gap_ids(state).values()):
            return True
        if activation_catalog(state):
            return True
        return any(
            evidence.evidence_type == "file_transfer_cross_host"
            and evidence.data.get("success")
            and evidence.data.get("target_host_id") not in state.scope.host_ids
            and not any(evidence.data.get("target_host_id") in item.candidate_host_ids for item in state.scope_expansions)
            for evidence in state.evidence
        )

    def _map_action(self, state: InvestigationState, name: str, args: dict[str, Any], call_id: str) -> InvestigationAction:
        if name in self.domain_tool_names:
            parameters = {key: value for key, value in args.items() if key != "gap_id" and value is not None}
            return EvidenceRequest(
                tool_name=name,
                objective=f"收集 {name} 对应证据缺口 {args.get('gap_id', '')} 的证据",
                gap_id=str(args.get("gap_id", "")),
                parameters=parameters,
            )
        if name == "analyze_evidence":
            return self._analysis_action(state, list(args.get("evidence_refs") or []))
        if name == "activate_scenario":
            return ScenarioActivationRequest(
                scenario=str(args.get("scenario", "")),
                objective=f"依据既有证据激活调查场景 {args.get('scenario', '')}",
                reason_refs=[str(item) for item in args.get("reason_refs") or []],
            )
        if name == "request_scope_expansion":
            return self._scope_action(state, args)
        if name == "finish_investigation":
            return self._finish_action(
                state,
                objective=str(args.get("objective") or "现有证据已足以形成结论，结束调查并生成报告"),
            )
        raise ValueError(f"Model requested an unregistered tool: {name}")

    def _analysis_action(self, state: InvestigationState, evidence_refs: list[str]) -> InvestigationAction:
        refs = sorted(set(evidence_refs))
        obligation = next(
            (
                item
                for item in state.analysis_obligations
                if item.status == "pending" and set(item.evidence_refs) == set(refs)
            ),
            None,
        )
        if obligation is None:
            # The model cited evidence that does not resolve to a pending
            # analysis obligation. Do not silently run an unrelated analyzer;
            # hand back a finish so Policy re-evaluates mandatory closure.
            return self._finish_action(state)
        return AnalysisRequest(
            tool_name=obligation.tool_name,
            objective=f"运行确定性分析 {obligation.tool_name}",
            evidence_refs=list(obligation.evidence_refs),
        )

    def _scope_action(self, state: InvestigationState, args: dict[str, Any]) -> ScopeRequest:
        evidence_ids = {item.evidence_id for item in state.evidence}
        proposed_refs = [str(item) for item in args.get("reason_evidence_refs") or []]
        normalized_refs = [item for item in proposed_refs if item in evidence_ids]
        domain_aliases = {"host_asset": "reputation", "auth": "process", "authentication": "process"}
        proposed_domains = [domain_aliases.get(str(item), str(item)) for item in args.get("requested_domains") or ["process", "file", "network"]]
        normalized_domains = list(dict.fromkeys(item for item in proposed_domains if item in state.scope.allowed_domains))
        return ScopeRequest(
            objective=str(args.get("objective") or "申请扩大调查范围"),
            requested_host_ids=[str(item) for item in args.get("requested_host_ids") or []],
            reason_evidence_refs=normalized_refs,
            reason_type=str(args.get("reason_type") or "related_host_evidence"),
            requested_domains=normalized_domains,
            start_time=state.scope.start_time,
            end_time=state.scope.end_time,
        )

    @staticmethod
    def _finish_action(
        state: InvestigationState,
        objective: str = "Finish after all currently eligible investigation actions were attempted",
    ) -> FinishRequest:
        resolved = [gap.gap_id for gap in state.evidence_gaps if gap.status == "resolved"]
        unresolved = [gap.gap_id for gap in state.evidence_gaps if gap.status != "resolved"]
        return FinishRequest(
            objective=objective,
            resolved_gap_ids=resolved,
            unresolved_gap_ids=unresolved,
        )

    def _messages(self, state: InvestigationState) -> list[Any]:
        payload = {
            "available_options": self._available_options(state),
            "state": json.loads(state_view(state, self.registry)),
        }
        messages: list[Any] = [
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=json.dumps(payload, ensure_ascii=False)),
        ]
        messages.extend(self._replay(state))
        return messages

    def _available_options(self, state: InvestigationState) -> dict[str, Any]:
        return {
            "eligible_gaps_by_domain": self.registry.eligible_gap_ids(state),
            "pending_analysis_obligations": [
                {"tool_name": item.tool_name, "evidence_refs": item.evidence_refs, "gap_ids": item.gap_ids}
                for item in state.analysis_obligations
                if item.status == "pending"
            ],
            "activatable_scenarios": activation_catalog(state),
            "authorized_host_ids": state.scope.host_ids,
        }

    def _replay(self, state: InvestigationState) -> list[Any]:
        messages: list[Any] = []
        packs_by_call = {item.request_call_id: item for item in state.evidence_packs}
        analysis_names = {item.name for item in self.registry.list() if item.kind == "analysis"}
        obligations_by_key = {
            (item.tool_name, tuple(sorted(item.evidence_refs))): item
            for item in state.analysis_obligations
        }
        for call in state.tool_calls[-12:]:
            if call.tool_name in self.domain_tool_names:
                model_tool_name = call.tool_name
                args = dict(call.parameters)
                content: dict[str, Any] = {}
                pack = packs_by_call.get(call.call_id)
                if pack is not None:
                    content = {
                        "outcome": pack.outcome,
                        "evidence_refs": pack.evidence_refs,
                        "returned_evidence_types": pack.returned_evidence_types,
                        "limitations": pack.limitations,
                    }
            elif call.tool_name in analysis_names:
                # The model invoked the fixed "analyze_evidence" facade; the
                # recorded tool_name is the concrete analyzer it resolved to.
                model_tool_name = "analyze_evidence"
                args = {"evidence_refs": list(call.parameters.get("evidence_refs") or [])}
                obligation = obligations_by_key.get(
                    (call.tool_name, tuple(sorted(call.parameters.get("evidence_refs") or [])))
                )
                content = (
                    {
                        "outcome": obligation.outcome,
                        "result_refs": obligation.result_refs,
                        "limitations": obligation.limitations,
                    }
                    if obligation is not None
                    else {}
                )
            elif call.tool_name == "activate_scenario":
                model_tool_name = "activate_scenario"
                args = dict(call.parameters)
                content = {
                    "scenario": call.parameters.get("scenario"),
                    "activated": call.status == "success",
                }
            else:
                continue
            if call.status in {"denied", "error"}:
                content["error"] = call.error
            messages.append(AIMessage(content="", tool_calls=[{
                "name": model_tool_name,
                "args": args,
                "id": call.call_id,
                "type": "tool_call",
            }]))
            messages.append(ToolMessage(
                content=json.dumps(content, ensure_ascii=False),
                tool_call_id=call.call_id,
                name=model_tool_name,
                status="error" if call.status in {"denied", "error"} else "success",
            ))
        return messages


# Compatibility import for existing callers. The implementation no longer uses Deep Agents.
DeepAgentsPlanner = StructuredJudgmentPlanner
