"""Authentication domain query (r11 gap remediation).

login_event（USER_LOGIN/USER_ACCT 投影）此前落入 ExtensionActivity 且无任何
查询工具覆盖——公钥驻留/隐藏账号案的"凭据被真实使用"半事实不可查。本测试
覆盖新链路：解析器 → 活动库 → 查询适配器 → 网关工具。
"""

from __future__ import annotations

from datetime import datetime, timezone

from threat_agent.contracts import (
    AuthenticationActivitiesInput,
    DatasetManifest,
    Scope,
)
from threat_agent.contracts.activity import AuthenticationActivity
from threat_agent.contracts.activity_query import AuthenticationActivityQuery
from threat_agent.data_foundation.adapters.activity_query import SQLiteActivityQueryAdapter
from threat_agent.data_foundation.adapters.activity_store import SQLiteActivityStore
from threat_agent.data_foundation.adapters.parsers import ReferenceEventParser
from threat_agent.data_foundation.application.ingestion import BatchIngestionService

UTC = timezone.utc


def _login_event(user: str, service: str, result: str = "success") -> dict:
    return {
        "event_id": f"login-{user}-{service}",
        "event_type": "login_event",
        "domain": "authentication",
        "source_system": "auditd-collector/1",
        "observed_at": "2026-10-10T12:00:00.000Z",
        "host_id": "server-01",
        "subject_refs": [f"user:{user}", "host:server-01"],
        "data": {"user": user, "source_ip": "", "result": result, "service": service},
    }


def _ingest(tmp_path, events: list[dict]) -> SQLiteActivityStore:
    store = SQLiteActivityStore(tmp_path / "activities.sqlite")
    parser = ReferenceEventParser()
    manifest = DatasetManifest(
        tenant_id="default",
        source_identity="test",
        dataset_id="ds",
        dataset_version="1",
        batch_id="b1",
        source_system="test",
        connector_version="t",
        parser_name=parser.name,
        parser_version=parser.version,
        expected_record_count=len(events),
    )
    BatchIngestionService(store, parser).ingest_payloads(manifest, events)
    return store


def test_login_events_become_authentication_activities(tmp_path):
    store = _ingest(tmp_path, [
        _login_event("svcmaint", "PAM:accounting"),
        _login_event("root", "sshd", result="failure"),
    ])
    rows = store.connection.execute(
        "SELECT payload_json FROM normalized_activities WHERE activity_type='authentication'"
    ).fetchall()
    assert len(rows) == 2
    activities = [AuthenticationActivity.model_validate_json(r[0]) for r in rows]
    by_user = {a.user_ref: a for a in activities}
    assert by_user["user:svcmaint"].operation == "accounting"
    assert by_user["user:root"].operation == "login"
    assert by_user["user:root"].result == "failure"
    store.close()


def test_query_authentication_filters_by_user(tmp_path):
    store = _ingest(tmp_path, [
        _login_event("svcmaint", "PAM:accounting"),
        _login_event("root", "sshd"),
    ])
    adapter = SQLiteActivityQueryAdapter(store)
    result = adapter.query_authentication(AuthenticationActivityQuery(
        tenant_id="default", case_id="case-1", run_id="run-1",
        query_id="q1", scope=Scope(host_ids=["server-01"]),
        user_refs=["user:svcmaint"],
    ))
    assert result.execution_boundary.returned_count == 1
    assert result.activities[0].user_ref == "user:svcmaint"
    assert result.evidence_references[0].activity_ref == result.activities[0].activity_id
    store.close()


def test_authentication_input_schema_accepts_filters():
    request = AuthenticationActivitiesInput.model_validate({
        "user_refs": ["user:svcmaint"], "results": ["success"],
    })
    assert request.user_refs == ["user:svcmaint"]
    assert request.results == ["success"]


def test_gateway_catalog_includes_authentication():
    from threat_agent.judgment.adapters.investigation_tools import _DOMAIN_TOOLS
    from threat_agent.judgment.application.data_tool_planner import TOOL_DEFINITIONS

    assert "query_authentication_activities" in _DOMAIN_TOOLS
    assert any(name == "query_authentication_activities" for name, _, _ in TOOL_DEFINITIONS)
