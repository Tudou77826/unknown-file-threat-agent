from __future__ import annotations

import json
from pathlib import Path

from ...contracts import CaseReadModel
from .read_model import build_case_read_model
from ...judgment.domain.models import InvestigationState
from ...presentation.projection.case_projector import case_read_payload


def report_payload(state: InvestigationState) -> dict:
    return case_read_payload(build_case_read_model(state))


def evaluation_payload(state: InvestigationState, expected: dict | None = None) -> dict:
    evidence_ids = {item.evidence_id for item in state.evidence}
    unsupported_edges = [
        relation.relation_id for relation in state.relations
        if not relation.evidence_refs or not set(relation.evidence_refs) <= evidence_ids
    ]
    fingerprints: set[tuple[str, str]] = set()
    duplicates = 0
    for call in state.tool_calls:
        fingerprint = (call.tool_name, json.dumps(call.parameters, sort_keys=True, ensure_ascii=False))
        if fingerprint in fingerprints:
            duplicates += 1
        fingerprints.add(fingerprint)
    critical_open = [
        gap.gap_id for gap in state.evidence_gaps
        if gap.priority == "critical" and gap.status not in {"resolved", "unresolvable"}
    ]
    expected = expected or {}
    expected_verdict = expected.get("verdict")
    expected_threat_type = expected.get("threat_type")
    required_findings = set(expected.get("required_findings") or [])
    actual_findings = {item.finding_type for item in state.findings}
    missing_required_findings = sorted(required_findings - actual_findings)
    verdict_match = expected_verdict is None or (state.verdict and state.verdict.level.value == expected_verdict)
    threat_type_match = expected_threat_type is None or (state.verdict and state.verdict.threat_type == expected_threat_type)
    passed = (
        state.finished
        and not state.verdict_validation_errors
        and not unsupported_edges
        and verdict_match
        and threat_type_match
        and not missing_required_findings
    )
    return {
        "case_id": state.case_id,
        "actual_verdict": state.verdict.level.value if state.verdict else None,
        "threat_type": state.verdict.threat_type if state.verdict else None,
        "expected_verdict": expected_verdict,
        "expected_threat_type": expected_threat_type,
        "verdict_match": bool(verdict_match),
        "threat_type_match": bool(threat_type_match),
        "required_findings": sorted(required_findings),
        "missing_required_findings": missing_required_findings,
        "tool_calls": len(state.tool_calls),
        "planner_decisions": len(state.planner_decisions),
        "active_scenarios": list(state.active_scenarios),
        "interpretations_count": len(state.interpretations),
        "evidence_packs_count": len(state.evidence_packs),
        "repair_actions_count": len(state.repair_actions),
        "pending_repair_actions": sum(item.status == "pending" for item in state.repair_actions),
        "top_scored_tools": [
            item.model_dump(mode="json")
            for item in sorted(state.tool_scores, key=lambda value: (-value.score, value.tool_name))[:10]
        ],
        "duplicate_tool_calls": duplicates,
        "denied_actions": sum(call.status == "denied" for call in state.tool_calls),
        "error_actions": sum(call.status == "error" for call in state.tool_calls),
        "repaired_decisions": sum(item.repaired for item in state.planner_decisions),
        "planner_fallbacks": sum(item.fallback_used for item in state.planner_decisions),
        "evidence_count": len(state.evidence),
        "facts_count": len(state.facts),
        "findings_count": len(state.findings),
        "relations_count": len(state.relations),
        "unresolved_critical_gaps": critical_open,
        "unsupported_path_edges": unsupported_edges,
        "verdict_validation_status": "PASS" if not state.verdict_validation_errors else "FAIL",
        "verdict_validation_errors": list(state.verdict_validation_errors),
        "result": "PASS" if passed else "FAIL",
    }


def write_reports(
    state: InvestigationState,
    output_dir: Path,
    expected: dict | None = None,
    read_model: CaseReadModel | None = None,
) -> tuple[Path, Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = case_read_payload(read_model) if read_model is not None else report_payload(state)
    json_path = output_dir / "report.json"
    md_path = output_dir / "report.md"
    evaluation_path = output_dir / "evaluation.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    evaluation_path.write_text(json.dumps(evaluation_payload(state, expected), ensure_ascii=False, indent=2), encoding="utf-8")
    verdict = payload["verdict"] or {}
    lines = [f"# Threat Investigation Report: {state.case_id}", "", f"- Verdict: `{verdict.get('level')}`", f"- Threat type: `{verdict.get('threat_type')}`", f"- Summary: {verdict.get('summary')}", "", "## Facts", ""]
    lines += [f"- {x['statement']} (`{x['fact_id']}`)" for x in payload["facts"]] or ["- None confirmed"]
    lines += ["", "## Findings", ""] + ([f"- {x['statement']} (`{x['finding_id']}`)" for x in payload["findings"]] or ["- None"])
    path_heading = "Attack path" if verdict.get("level") in {"confirmed_malicious", "likely_malicious", "suspicious"} else "Observed behavior path"
    lines += ["", f"## {path_heading}", ""] + ([f"- `{x['source_entity_ref']}` --{x['relation_type']}--> `{x['target_entity_ref']}`; evidence: {', '.join(x['evidence_refs'])}" for x in payload["attack_path"]] or ["- No validated path"])
    lines += ["", "## Evidence index", ""] + ([f"- `{x['evidence_id']}`: `{x['evidence_type']}` from `{x['source_system']}` at `{x.get('observed_at')}` ({x.get('raw_reference')})" for x in payload["evidence"]] or ["- None"])
    lines += ["", "## Analysis notes", ""] + ([f"- {x}" for x in payload["analysis_notes"]] or ["- None recorded"])
    lines += ["", "## Evidence packs", ""] + ([f"- `{x['pack_id']}`: `{x['tool_name']}` → `{x['target_gap_id']}`; outcome `{x['outcome']}`; evidence: {', '.join(x['evidence_refs']) or 'none'}" for x in payload["evidence_packs"]] or ["- None"])
    lines += ["", "## Repair actions", ""] + ([f"- `{x['repair_id']}`: `{x['repair_type']}` / `{x['status']}` — {x['reason']}" for x in payload["repair_actions"]] or ["- None"])
    lines += ["", "## Verdict validation", "", f"- Status: `{payload['verdict_validation']['status']}`"]
    lines += [f"- {x}" for x in payload["verdict_validation"]["errors"]]
    lines += ["", "## Limitations", ""] + ([f"- {x}" for x in payload["limitations"]] or ["- None recorded"])
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, md_path, evaluation_path
