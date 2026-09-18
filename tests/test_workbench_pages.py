"""Feature 17 workbench page regression tests.

These pages are server-rendered strings consumed by a browser; the two bugs
that reached review (a mismatched helper signature and a broken inline JS
handler) were invisible to every existing test. This module pins the page
contracts that matter: the approval card renders both standalone and inline,
the run page includes it when the run is parked, display labels replace raw
enums, and the checkpoint controls use data attributes rather than inlined
string concatenation.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from threat_agent.contracts import (
    ApprovalRequestReadModel,
    InvestigationRun,
    InvestigationRunReadModel,
    OperationalEvent,
)
from threat_agent.presentation import InMemoryCaseReadStore
from threat_agent.presentation.api import pages
from threat_agent.presentation.api.routes import create_app

TENANT = "default"


def _run(status: str = "awaiting_approval", **overrides) -> InvestigationRun:
    payload = dict(
        tenant_id=TENANT, case_id="case-1", run_id="run-1",
        source_identity="test", status=status, stage="approval",
        graph_thread_id=f"{TENANT}/case-1/run-1",
    )
    payload.update(overrides)
    return InvestigationRun(**payload)


def _event(sequence: int, kind: str, message: str, node: str = "approve") -> OperationalEvent:
    return OperationalEvent(
        tenant_id=TENANT, case_id="case-1", source_identity="test", run_id="run-1",
        event_id=f"e-{sequence}", sequence=sequence, event_type="run", stage="approval",
        node=node, details={"kind": kind, "message": message}, correlation_id="c",
    )


class _RunService:
    def __init__(self, status: str = "awaiting_approval"):
        self.status = status

    def start(self, dataset_id, profile_id):  # pragma: no cover - unused
        return "run-1"

    def list_runs(self):
        return []

    def get_investigation(self, run_id):
        if run_id != "run-1":
            return None
        return InvestigationRunReadModel(
            run=_run(self.status),
            reference_dataset_id="ds",
            profile_id="l3-attribution-and-assets",
            events=[_event(1, "round", "第 1 轮：查询了进程与命令。")],
        )

    def knowledge_stats(self):
        return {"total": 1, "by_status": {"available": 1}, "by_category": {}, "recent": []}

    def get_trajectory(self, run_id):
        from threat_agent.contracts import TrajectoryReadModel

        return TrajectoryReadModel(run_id=run_id, case_id="case-1")


class _ApprovalService:
    def list_pending(self):
        return [
            ApprovalRequestReadModel(
                run_id="run-1",
                case_id="case-1",
                plan={
                    "status": "approval_required",
                    "actions": [
                        {
                            "action_type": "isolate_host",
                            "approval_class": "security_lead",
                            "rationale": "确认外联后隔离受影响主机",
                            "expected_impact": "业务中断 5 分钟",
                        }
                    ],
                },
            )
        ]

    def decide(self, run_id, decision):  # pragma: no cover - unused
        return {}


def _client(**kwargs):
    return TestClient(create_app(InMemoryCaseReadStore(), None, **kwargs))


# --------------------------------------------------------------- approval card


def test_approval_card_renders_standalone_and_inline():
    pending = _ApprovalService().list_pending()[0]
    standalone = pages.approval_card_html(pending)
    inline = pages.approval_card_html(pending, inline=True)

    for html in (standalone, inline):
        assert "等待你的审批" in html
        assert "隔离受影响主机" in html  # action type translated
        assert "需安全负责人审批" in html  # approval class translated
        assert "批准＝按方案执行" in html  # four-state semantics documented
        assert "decideApproval('run-1','accept')" in html

    assert "class='card approval-card'" in standalone
    assert "approval-card inline" in inline and "class='card approval-card'" not in inline


def test_run_page_renders_inline_approval_when_parked():
    """Regression: the run page used to 500 here (helper signature mismatch)."""

    client = _client(
        demo_run_service=_RunService("awaiting_approval"),
        approval_service=_ApprovalService(),
    )
    response = client.get("/workbench/runs/run-1")
    assert response.status_code == 200
    assert "approval-card inline" in response.text
    assert "等待你的审批" in response.text
    # The banner must not send the operator away: the decision is inline.
    assert "下方流程中可直接决策" in response.text


def test_run_page_without_pending_approval_still_renders():
    client = _client(
        demo_run_service=_RunService("completed"),
        approval_service=_ApprovalService(),
    )
    response = client.get("/workbench/runs/run-1")
    assert response.status_code == 200
    assert "approval-card inline" not in response.text


# --------------------------------------------------------------- debug controls


def test_checkpoint_controls_use_data_attributes_not_inline_concatenation():
    """Regression: inlined `onclick="showState(''+c.id+'')"` broke at runtime."""

    client = _client(demo_run_service=_RunService("completed"))
    body = client.get("/workbench/runs/run-1").text
    assert 'data-act="state"' in body or "data-act" in body
    assert "onclick=\"showState(''" not in body
    assert "c.checkpoint_id+'')" not in body


# --------------------------------------------------------------- display gate


def test_pipeline_bar_exposes_stage_order_for_live_updates():
    client = _client(demo_run_service=_RunService("completed"))
    body = client.get("/workbench/runs/run-1").text
    assert "id='pipeline'" in body
    assert "data-stage='intake'" in body
    assert "data-order=" in body


def test_event_kind_labels_are_translated():
    client = _client(demo_run_service=_RunService("completed"))
    body = client.get("/workbench/runs/run-1").text
    # Round events must read as Chinese narrative, never as the raw kind.
    assert "调查轮次" in body
    assert ">round<" not in body


def test_display_dictionaries_cover_contract_enums():
    """The translation gate must know every value the contracts can emit."""

    from threat_agent.contracts.response import ResponsePlan

    # approval_class is a Literal on the response contract; every member needs
    # a human label or the UI leaks the raw enum.
    field = ResponsePlan.model_fields["actions"].annotation
    assert pages.APPROVAL_CLASS_ZH.get("security_lead")
    assert pages.APPROVAL_CLASS_ZH.get("business_owner")
    assert pages.APPROVAL_CLASS_ZH.get("operator")
    assert pages.PUBLICATION_ZH.get("grounded") and pages.PUBLICATION_ZH.get("fallback")
    assert pages.PLAN_STATUS_ZH.get("approval_required")


def test_knowledge_page_consumes_enriched_stats():
    """Regression: the page read label keys that only the JSON endpoint added."""

    client = _client(
        demo_run_service=_RunService("completed"),
        knowledge_overview={
            "adapter": "reference",
            "profile": "standard",
            "catalog": {
                "supplier_id": "reference-corpus",
                "profile": "standard",
                "categories": [
                    {
                        "category": "attack_technique",
                        "items": [
                            {
                                "knowledge_id": "ke-judgment-poison-001",
                                "version": "1",
                                "title": "注入演练条目",
                                "summary": "s",
                                "restricted_to_tenant": None,
                            }
                        ],
                    }
                ],
            },
        },
    )
    body = client.get("/workbench/knowledge").text
    assert "攻击技术库" in body  # category label, not the raw key
    assert "注入演练样本" in body  # poison badge keyed off the id, not tenant
    assert "SupplierRetrievalPort" not in body
    assert "SecurityKnowledgeService" not in body


# ---------------------------------------------------------------------------
# Feature 18: the run-page knowledge panel must say WHAT was consulted and
# WHICH items came back — not just "已命中". Old events (no items in details)
# fall back to the translated message line.

from types import SimpleNamespace


def _knowledge_entry(detail, summary="知识咨询 lookup_attack_technique 完成：available"):
    return SimpleNamespace(kind="knowledge", summary=summary, detail=detail)


def test_knowledge_card_lists_hit_items():
    card = pages.knowledge_card_html(_knowledge_entry({
        "entry": "lookup_attack_technique",
        "status": "available",
        "items": [
            {"knowledge_id": "T1543.002", "version": "19.2",
             "title": "Systemd 服务（Systemd Service，T1543.002）"},
            {"knowledge_id": "T1095", "version": "19.2", "title": "非应用层协议（T1095）"},
        ],
    }))
    assert "查询攻击技术库" in card
    assert "已命中" in card and "pill ok" in card
    assert "命中 2 条" in card
    assert "T1543.002" in card and "Systemd 服务" in card
    assert "T1095" in card


def test_knowledge_card_baseline_entry_label():
    card = pages.knowledge_card_html(_knowledge_entry({
        "entry": "baseline",
        "status": "available",
        "items": [{"knowledge_id": "T1053.003", "version": "19.2", "title": "计划任务：Cron"}],
    }, summary="基线知识检索完成：available"))
    assert "基线检索（研判指引）" in card
    assert "T1053.003" in card


def test_knowledge_card_falls_back_for_legacy_events():
    card = pages.knowledge_card_html(_knowledge_entry({
        "entry": "consult_judgment_experience",
        "status": "available",
    }))
    # No items in details: the message line is shown, no fabricated entries.
    assert "查询研判经验" in card
    assert "已命中" in card
    assert "know-item" not in card


def test_knowledge_card_shows_failure_status_and_limitations():
    card = pages.knowledge_card_html(_knowledge_entry({
        "entry": "baseline",
        "status": "degraded",
        "limitations": ["[attack_technique] 知识源访问超时，未获得任何条目"],
    }, summary="基线知识检索完成：degraded"))
    assert "pill warn" in card and "降级" in card
    assert "知识源访问超时" in card
    assert "know-item" not in card
