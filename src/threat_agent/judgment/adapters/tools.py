from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Callable

from ..domain.analyzers import ANALYZERS
from ...contracts import EvidenceQuery
from ...data_foundation import EvidenceQueryPort, RepositoryEvidenceQueryAdapter
from ..domain.models import EvidenceBundle, FactFindingBundle, InvestigationState
from ..application.orchestration import score_tool
from ..application.native_tool_calling import (
    ActivateScenarioInput,
    AnalyzeEvidenceInput,
    DomainEvidenceQueryInput,
    FinishInvestigationInput,
    RequestScopeExpansionInput,
)
from ...data_foundation.adapters.repository import EvidenceRepository


# Domain tools are the fixed, cache-stable surface the LLM sees. Each maps to a
# single data domain; the gap -> evidence_type resolution stays deterministic.
DOMAIN_TOOL_DOMAINS: dict[str, str] = {
    "query_process_evidence": "process",
    "query_file_evidence": "file",
    "query_network_evidence": "network",
    "query_persistence_evidence": "persistence",
    "query_reputation_evidence": "reputation",
}


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    kind: str
    domain: str
    description: str
    handler: Callable[..., Any]
    input_schema: dict[str, Any]
    provides_evidence_types: frozenset[str] = frozenset()
    requires_evidence_types: frozenset[str] = frozenset()
    requirements_mode: str = "all"
    resolves_gap_types: frozenset[str] = frozenset()
    repeat_policy: str = "new_parameters"


class ToolRegistry:
    def __init__(
        self,
        repository: EvidenceRepository | EvidenceQueryPort,
        *,
        query_default_limit: int = 1000,
        query_max_limit: int = 5000,
    ):
        self.repository = repository
        self.query_default_limit = query_default_limit
        self.query_max_limit = query_max_limit
        self.evidence_query_port: EvidenceQueryPort = (
            repository
            if hasattr(repository, "query_evidence")
            else RepositoryEvidenceQueryAdapter(repository)  # type: ignore[arg-type]
        )
        self._tools: dict[str, ToolDefinition] = {}
        self._domain_tools: dict[str, str] = dict(DOMAIN_TOOL_DOMAINS)
        self._domain_evidence_types: dict[str, frozenset[str]] = {}
        evidence_specs = [
            ("query_process_execution", "process", {"process_exec"}, "Find executions of the investigated file"),
            ("query_process_relations", "process", {"process_parent_relation"}, "Find parent-child relations for scoped process instances"),
            ("query_child_process_execution", "process", {"child_process_exec"}, "Find commands executed by children of the investigated process"),
            ("query_login_sessions", "process", {"login_session"}, "Find login sessions associated with process ancestry"),
            ("query_file_activity", "file", {"file_event"}, "Find creation, write, rename and deletion events for scoped files"),
            ("query_process_network", "network", {"network_connection"}, "Find network connections attributed to scoped process instances"),
            ("query_dns_activity", "network", {"dns_query"}, "Find DNS activity attributed to scoped process instances"),
            ("query_socket_activity", "network", {"socket_io"}, "Find socket reads and writes for remote-command correlation"),
            ("query_systemd_events", "persistence", {"systemd_event"}, "Find systemd unit creation, enablement and start events"),
            ("query_cron_events", "persistence", {"cron_event"}, "Find cron persistence changes that reference scoped files"),
            ("query_package_provenance", "reputation", {"package_provenance"}, "Find package ownership and signature provenance for the file"),
            ("query_approved_endpoints", "reputation", {"approved_endpoint"}, "Find approved endpoint and operations-baseline matches"),
            ("query_file_origin", "file", {"file_create", "file_download", "file_transfer", "archive_extraction", "package_install", "web_upload"}, "Find candidate creation, download, transfer, extraction, package or web-upload origin events"),
            ("query_file_downloads", "file", {"file_download"}, "Find network download events that produced the investigated file"),
            ("query_file_transfer", "file", {"file_transfer"}, "Find SCP, SFTP, rsync or equivalent transfer events for the investigated file"),
            ("query_archive_extraction", "file", {"archive_extraction"}, "Find archive extraction events that produced the investigated file"),
            ("query_package_installation", "file", {"package_install"}, "Find package installation records that produced the investigated file"),
            ("query_web_upload_activity", "file", {"web_upload"}, "Find web-service upload or drop events that produced the investigated file"),
            ("query_sensitive_file_access", "file", {"sensitive_file_access"}, "Find successful reads of credential, key, token, cookie, configuration and other sensitive files"),
            ("query_discovery_commands", "process", {"discovery_command"}, "Find scoped commands used to discover files, accounts, mounts, databases or cloud resources"),
            ("query_archive_activity", "file", {"archive_create", "archive_member"}, "Find archive creation and input-member lineage for potential data staging"),
            ("query_staging_directory_activity", "file", {"staging_file"}, "Find sensitive data copied into temporary, hidden or staging directories"),
            ("query_process_network_bytes", "network", {"network_transfer"}, "Find process-attributed network byte transfers"),
            ("query_data_transfer", "network", {"network_transfer", "http_upload"}, "Find successful outbound data transfers attributed to scoped processes or process trees"),
            ("query_http_activity", "network", {"http_upload"}, "Find process-attributed HTTP upload requests and response outcomes"),
            ("query_dns_payload_activity", "network", {"dns_query"}, "Find process-attributed DNS queries for tunnel-pattern analysis"),
            ("query_data_transfer_baseline", "reputation", {"transfer_baseline"}, "Find approved backup, synchronization or transfer baselines for the observed process and endpoint"),
            ("query_bulk_file_modification", "file", {"bulk_file_metric"}, "Find high-rate file modifications and affected-directory counts"),
            ("query_file_content_change", "file", {"file_content_change"}, "Find entropy, header and content changes for modified files"),
            ("query_file_rename_patterns", "file", {"file_rename_pattern"}, "Find repeated extension and rename patterns"),
            ("query_backup_destruction", "persistence", {"backup_destruction"}, "Find backup deletion and disablement outcomes"),
            ("query_snapshot_activity", "persistence", {"snapshot_activity"}, "Find snapshot deletion and recovery-point changes"),
            ("query_service_disruption", "persistence", {"service_disruption"}, "Find service stops attributed to the process tree"),
            ("query_ransom_note_activity", "file", {"ransom_note"}, "Find ransom-note creation and distribution events"),
            ("query_destructive_commands", "process", {"destructive_command"}, "Find process-attributed destructive recovery commands"),
            ("query_ransomware_baseline", "reputation", {"authorized_batch_baseline"}, "Find approved encryption, deployment, compression and log-rotation baselines"),
            ("query_hash_presence", "file", {"hash_presence"}, "Find the investigated hash on approved in-scope hosts"),
            ("query_internal_connections", "network", {"internal_connection"}, "Find internal connections between scoped hosts"),
            ("query_remote_login_sessions", "process", {"remote_login_session"}, "Find cross-host SSH and authenticated remote sessions"),
            ("query_account_activity_across_hosts", "process", {"cross_host_account_activity"}, "Find use of the same account across scoped hosts"),
            ("query_file_transfer_across_hosts", "file", {"file_transfer_cross_host"}, "Find file transfers that identify source and target hosts"),
            ("query_shared_endpoint_hosts", "network", {"shared_endpoint_host"}, "Find hosts communicating with the same endpoint"),
            ("query_host_asset_context", "reputation", {"host_asset_context"}, "Find asset roles and approved deployment relationships for candidate hosts"),
        ]
        query_schema = {
            "type": "object",
            "properties": {
                "host_id": {"type": "string"},
                "entity_ids": {"type": "array", "items": {"type": "string"}},
                "start_time": {"type": ["string", "null"], "format": "date-time"},
                "end_time": {"type": ["string", "null"], "format": "date-time"},
                "filters": {"type": "object"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 5000},
            },
            "additionalProperties": False,
        }
        for name, domain, provided, description in evidence_specs:
            self._domain_evidence_types.setdefault(domain, set()).update(provided)
            self.register(ToolDefinition(
                name=name,
                kind="evidence",
                domain=domain,
                description=description,
                handler=self._query,
                input_schema=query_schema,
                provides_evidence_types=frozenset(provided),
            ))
        analysis_domains = {
            "analyze_execution": "process",
            "analyze_process_chain": "process",
            "analyze_network": "network",
            "analyze_remote_command": "network",
            "analyze_persistence": "persistence",
            "analyze_reputation": "reputation",
            "analyze_file_provenance": "file",
            "analyze_sensitive_discovery": "process",
            "analyze_credential_access": "file",
            "analyze_data_staging": "file",
            "analyze_data_transfer": "network",
            "analyze_dns_tunneling": "network",
            "analyze_https_exfiltration": "network",
            "analyze_dns_exfiltration": "network",
            "analyze_bulk_file_impact": "file",
            "analyze_probable_file_encryption": "file",
            "analyze_recovery_inhibition": "persistence",
            "analyze_ransom_note": "file",
            "analyze_service_disruption": "persistence",
            "analyze_ransomware_chain": "file",
            "analyze_cross_host_path": "process",
            "analyze_cross_host_lead": "file",
        }
        requirements = {
            "analyze_execution": {"process_exec"},
            "analyze_process_chain": {"process_parent_relation"},
            "analyze_network": {"network_connection"},
            "analyze_remote_command": {"network_connection", "socket_io", "child_process_exec", "process_parent_relation"},
            "analyze_persistence": {"systemd_event"},
            "analyze_reputation": {"package_provenance", "approved_endpoint"},
            "analyze_file_provenance": {"file_create", "file_download", "file_transfer", "archive_extraction", "package_install", "web_upload"},
            "analyze_sensitive_discovery": {"discovery_command"},
            "analyze_credential_access": {"sensitive_file_access"},
            "analyze_data_staging": {"archive_create", "archive_member", "staging_file"},
            "analyze_data_transfer": {"network_transfer", "http_upload"},
            "analyze_dns_tunneling": {"dns_query"},
            "analyze_https_exfiltration": {"sensitive_file_access", "archive_create", "archive_member", "network_transfer", "transfer_baseline"},
            "analyze_dns_exfiltration": {"sensitive_file_access", "archive_create", "archive_member", "dns_query", "transfer_baseline"},
            "analyze_bulk_file_impact": {"bulk_file_metric"},
            "analyze_probable_file_encryption": {"file_content_change", "file_rename_pattern"},
            "analyze_recovery_inhibition": {"backup_destruction", "snapshot_activity", "destructive_command"},
            "analyze_ransom_note": {"ransom_note"},
            "analyze_service_disruption": {"service_disruption"},
            "analyze_ransomware_chain": {"bulk_file_metric", "file_content_change", "file_rename_pattern", "ransom_note", "authorized_batch_baseline"},
            "analyze_cross_host_path": {"file_transfer_cross_host", "hash_presence", "remote_login_session", "host_asset_context"},
            "analyze_cross_host_lead": {"file_transfer_cross_host", "internal_connection", "shared_endpoint_host"},
        }
        resolved_gap_types = {
            "analyze_execution": {"execution"},
            "analyze_process_chain": {"process_chain"},
            "analyze_network": {"network_behavior"},
            "analyze_remote_command": {"remote_command"},
            "analyze_persistence": {"persistence"},
            "analyze_reputation": {"counter_evidence"},
            "analyze_file_provenance": {"file_origin"},
            "analyze_sensitive_discovery": {"sensitive_discovery"},
            "analyze_credential_access": {"sensitive_access"},
            "analyze_data_staging": {"data_staging"},
            "analyze_data_transfer": {"data_transfer"},
            "analyze_dns_tunneling": {"dns_tunnel", "data_transfer"},
            "analyze_https_exfiltration": {"exfiltration", "transfer_counter"},
            "analyze_dns_exfiltration": {"exfiltration", "transfer_counter"},
            "analyze_bulk_file_impact": {"bulk_file_impact"},
            "analyze_probable_file_encryption": {"file_encryption"},
            "analyze_recovery_inhibition": {"recovery_inhibition"},
            "analyze_ransom_note": {"ransom_note"},
            "analyze_service_disruption": {"service_disruption"},
            "analyze_ransomware_chain": {"ransomware_chain", "ransomware_counter"},
            "analyze_cross_host_path": {"cross_host_confirmation", "cross_host_counter"},
            "analyze_cross_host_lead": {"cross_host_lead"},
        }
        requirement_modes = {
            "analyze_file_provenance": "any",
            "analyze_data_transfer": "any",
            "analyze_data_staging": "any",
            "analyze_recovery_inhibition": "any",
            "analyze_cross_host_lead": "any",
        }
        for name, analyzer in ANALYZERS.items():
            domain = analysis_domains[name]
            self.register(ToolDefinition(
                name=name,
                kind="analysis",
                domain=domain,
                description=f"Run deterministic {domain} analysis on existing evidence",
                handler=analyzer,
                input_schema={
                    "type": "object",
                    "properties": {"evidence_refs": {"type": "array", "items": {"type": "string"}, "minItems": 1}},
                    "required": ["evidence_refs"],
                    "additionalProperties": False,
                },
                requires_evidence_types=frozenset(requirements[name]),
                requirements_mode=requirement_modes.get(name, "all"),
                resolves_gap_types=frozenset(resolved_gap_types[name]),
                repeat_policy="new_evidence",
            ))

    def register(self, definition: ToolDefinition) -> None:
        if definition.name in self._tools:
            raise ValueError(f"Duplicate tool: {definition.name}")
        self._tools[definition.name] = definition

    def get(self, name: str) -> ToolDefinition:
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}")
        return self._tools[name]

    def list(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    def catalog(self, state: InvestigationState) -> list[dict[str, Any]]:
        evidence_types = {e.evidence_type for e in state.evidence if e.status.value == "available"}
        calls = {call.tool_name for call in state.tool_calls if call.status not in {"denied", "error"}}
        open_gaps = [gap for gap in state.evidence_gaps if gap.status in {"open", "querying", "evidence_collected", "partially_resolved"}]
        collected_types = {e.evidence_type for e in state.evidence if e.status.value == "available"}
        result = []
        for tool in self.list():
            target_host_tools = {"query_hash_presence", "query_remote_login_sessions", "query_account_activity_across_hosts", "query_host_asset_context"}
            if tool.name in target_host_tools and "cross_host" in state.active_scenarios and not any(item.approval_status == "approved" for item in state.scope_expansions):
                continue
            if tool.domain not in state.scope.allowed_domains and tool.domain != "execution":
                continue
            missing = sorted(tool.requires_evidence_types - evidence_types)
            requirements_met = (
                bool(tool.requires_evidence_types & evidence_types)
                if tool.requirements_mode == "any"
                else not missing
            )
            if tool.kind == "analysis" and not requirements_met:
                continue
            compatible_gap_ids = [
                gap.gap_id for gap in open_gaps
                if tool.provides_evidence_types & (set(gap.required_evidence_types) - collected_types)
            ]
            if tool.kind == "evidence" and not compatible_gap_ids:
                continue
            eligible_evidence_refs = sorted(
                e.evidence_id for e in state.evidence
                if e.status.value == "available" and e.evidence_type in tool.requires_evidence_types
            )
            if tool.kind == "analysis":
                obligations = [
                    item for item in state.analysis_obligations
                    if item.tool_name == tool.name and item.status == "pending"
                ]
                if not obligations:
                    continue
                eligible_evidence_refs = sorted({ref for item in obligations for ref in item.evidence_refs})
                compatible_gap_ids = sorted({gap_id for item in obligations for gap_id in item.gap_ids})
            compatible_gaps = [gap for gap in state.evidence_gaps if gap.gap_id in compatible_gap_ids]
            matching_roles = [
                role for role in state.evidence_roles
                if role.status != "satisfied" and (tool.provides_evidence_types or tool.requires_evidence_types) & set(role.required_evidence_types)
            ]
            score = score_tool(state, tool, compatible_gaps, matching_roles, tool.name in calls)
            result.append({
                "tool_name": tool.name,
                "kind": tool.kind,
                "domain": tool.domain,
                "description": tool.description,
                "input_schema": tool.input_schema,
                "provides_evidence_types": sorted(tool.provides_evidence_types),
                "requires_evidence_types": sorted(tool.requires_evidence_types),
                "compatible_gap_ids": compatible_gap_ids,
                "eligible_evidence_refs": eligible_evidence_refs,
                "analysis_obligation_ids": [
                    item.obligation_id for item in state.analysis_obligations
                    if item.tool_name == tool.name and item.status == "pending"
                ],
                "already_called": tool.name in calls,
                "repeat_policy": tool.repeat_policy,
                "priority_score": score.score,
                "score_breakdown": score.model_dump(mode="json"),
            })
        return sorted(result, key=lambda item: (-item["priority_score"], item["tool_name"]))

    def _query(self, domain: str, evidence_types: frozenset[str], state: InvestigationState, parameters: dict[str, Any]) -> EvidenceBundle:
        fingerprint = json.dumps(
            {
                "case_id": state.case_id,
                "iteration": state.budget.iterations_used,
                "domain": domain,
                "evidence_types": sorted(evidence_types),
                "parameters": parameters,
            },
            sort_keys=True,
            default=str,
        )
        query = EvidenceQuery(
            tenant_id=str(state.raw_input.get("tenant_id") or "default"),
            case_id=state.case_id,
            source_identity="judgment-tool-registry",
            query_id="equery-" + hashlib.sha256(fingerprint.encode()).hexdigest()[:16],
            domain=domain,
            evidence_types=sorted(evidence_types),
            scope=state.scope,
            parameters=parameters,
            limit=min(
                int(parameters.get("limit", self.query_default_limit)),
                self.query_max_limit,
            ),
        )
        return self.evidence_query_port.query_evidence(query)

    def invoke(self, name: str, state: InvestigationState, parameters: dict[str, Any] | None = None) -> EvidenceBundle | FactFindingBundle:
        tool = self.get(name)
        parameters = parameters or {}
        if tool.kind == "evidence":
            return tool.handler(tool.domain, tool.provides_evidence_types, state, parameters)
        return tool.handler(
            state,
            evidence_refs=list(parameters.get("evidence_refs") or []),
            parameters=parameters,
        )

    # -- Native domain tools -------------------------------------------------
    # The LLM sees a fixed set of domain tools (stable schema -> cache friendly).
    # The gap -> evidence_type resolution stays deterministic and lives here.

    def domain_tool_names(self) -> tuple[str, ...]:
        return tuple(self._domain_tools)

    def native_tool_specs(self) -> list[tuple[str, type, str]]:
        return [
            ("query_process_evidence", DomainEvidenceQueryInput, "查询进程域证据，解决进程执行、进程树、子进程命令等调查问题"),
            ("query_file_evidence", DomainEvidenceQueryInput, "查询文件域证据，解决文件来源、敏感访问、归档、加密等调查问题"),
            ("query_network_evidence", DomainEvidenceQueryInput, "查询网络域证据，解决外联、DNS、数据传输等调查问题"),
            ("query_persistence_evidence", DomainEvidenceQueryInput, "查询持久化域证据，解决持久化配置、破坏备份、服务停用等调查问题"),
            ("query_reputation_evidence", DomainEvidenceQueryInput, "查询信誉与基线证据，解决软件来源、批准端点、备份基线等反证问题"),
            ("analyze_evidence", AnalyzeEvidenceInput, "对已收集证据运行确定性分析，产出事实与发现"),
            ("activate_scenario", ActivateScenarioInput, "依据已存在证据动态激活一个已审核的调查场景模板"),
            ("request_scope_expansion", RequestScopeExpansionInput, "发现授权范围外的相关主机时发起范围扩大审批"),
            ("finish_investigation", FinishInvestigationInput, "证据足以形成结论时结束调查并生成报告"),
        ]

    def domain_for_tool(self, tool_name: str) -> str:
        return self._domain_tools[tool_name]

    def eligible_gap_ids(self, state: InvestigationState) -> dict[str, list[str]]:
        """Return, per domain, the open gaps that still need evidence in it."""
        collected = {e.evidence_type for e in state.evidence if e.status.value == "available"}
        open_gaps = [
            gap for gap in state.evidence_gaps
            if gap.status in {"open", "querying", "evidence_collected", "partially_resolved"}
        ]
        result: dict[str, list[str]] = {domain: [] for domain in self._domain_tools.values()}
        for gap in open_gaps:
            for domain in self._domain_tools.values():
                domain_types = set(self._domain_evidence_types.get(domain, set()))
                missing = (set(gap.required_evidence_types) & domain_types) - collected
                if missing:
                    result[domain].append(gap.gap_id)
        return result

    def resolve_domain_gap(self, state: InvestigationState, domain: str, gap_id: str) -> frozenset[str]:
        gap = next((item for item in state.evidence_gaps if item.gap_id == gap_id), None)
        if gap is None:
            raise KeyError(f"Unknown evidence gap: {gap_id}")
        types = set(gap.required_evidence_types) & set(self._domain_evidence_types.get(domain, set()))
        if not types:
            raise ValueError(f"Gap {gap_id} is not addressable from domain {domain}")
        return frozenset(types)

    def invoke_domain_evidence(self, state: InvestigationState, tool_name: str, gap_id: str, parameters: dict[str, Any]) -> tuple[EvidenceBundle, frozenset[str]]:
        domain = self._domain_tools[tool_name]
        evidence_types = self.resolve_domain_gap(state, domain, gap_id)
        query_parameters = {key: value for key, value in parameters.items() if value is not None}
        return self._query(domain, evidence_types, state, query_parameters), evidence_types
