from __future__ import annotations

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from middleware_harness import TENANT, seed_store
from threat_agent.case_management import SingleHostBoundaryPolicy
from threat_agent.contracts import (
    AlertQuery, AssessmentQuery, AssetInfo, DataQueryContext, DatasetManifest,
    FileHash, FileReputation, InvestigationToolLedger, QueryPage, ReputationMatch,
    Scope, SourceAssessment, ToolRuntimeContext, UnknownFileAlert,
)
from threat_agent.data_foundation import (
    BatchIngestionService, DataAccessError, DataQueryFailed, ReferenceEventParser,
    SQLiteInvestigationDataAdapter, SituationalAwarenessDataAdapter, UnsupportedDataQuery,
)
from threat_agent.judgment import InvestigationToolGateway


NOW = datetime(2026, 4, 23, 4, tzinfo=timezone.utc)
FILE_HASH = FileHash(algorithm="sha256", digest="a" * 64)


def _context() -> DataQueryContext:
    return DataQueryContext(
        tenant_id=TENANT,
        scope=Scope(host_ids=["host-1"], start_time=NOW.replace(hour=0),
                    end_time=NOW.replace(hour=23)),
    )


def _alert(**overrides) -> UnknownFileAlert:
    return UnknownFileAlert.model_validate({
        "tenant_id": TENANT, "source_system": "siem", "source_record_id": "alert-1",
        "host_ref": "host-1", "file_hash": FILE_HASH, "file_path": "/tmp/a",
        "detected_at": NOW, **overrides,
        "created_at": NOW,
    })


def _query(cls=AlertQuery, **overrides):
    return cls.model_validate({**_context().model_dump(), **overrides})


def test_database_activities_and_ir_context_can_be_composed(tmp_path):
    store = seed_store(tmp_path)
    try:
        def ir_reputation(context, file_hash):
            return FileReputation(
                tenant_id=context.tenant_id, source_system="siem-ir", file_hash=file_hash,
                queried_lists=["baseline", "blocklist"], queried_at=NOW,
                matches=[ReputationMatch(list_name="baseline", source_record_id="baseline-1"),
                         ReputationMatch(list_name="blocklist", source_record_id="blocklist-1")],
            )

        data = SituationalAwarenessDataAdapter(
            SQLiteInvestigationDataAdapter(store), file_reputation=ir_reputation,
            alerts=lambda query: QueryPage(records=[_alert()], next_cursor="page-2"),
        )
        context = ToolRuntimeContext(
            tenant_id=TENANT, case_id="case-a", run_id="run-a", scope=_context().scope,
        )
        gateway = InvestigationToolGateway(
            data, SingleHostBoundaryPolicy(tenant_id=TENANT, case_id="case-a", run_id="run-a"),
        )
        ledger = InvestigationToolLedger()
        result = gateway.invoke("query_process_activities", {}, context, ledger)
        assert [activity.activity_id for activity in result.activities] == ["activity-p1"]
        assert ledger.authorized_activity_refs == ["activity-p1"]
        raw = gateway.invoke("get_raw_records", {"activity_refs": ["activity-p1"]}, context, ledger)
        assert raw.records[0].source_record_id == "p1"
        reputation = data.query_file_reputation(_context(), FILE_HASH)
        assert [match.list_name for match in reputation.matches] == ["baseline", "blocklist"]
        assert reputation.file_hash == FILE_HASH
        page = data.query_alerts(_query())
        assert page.next_cursor == "page-2"
        assert QueryPage[UnknownFileAlert].model_validate_json(page.model_dump_json()).records[0] == _alert()
    finally:
        store.close()


def test_authentication_query_reaches_the_existing_tool(tmp_path):
    store = seed_store(tmp_path)
    try:
        parser = ReferenceEventParser()
        BatchIngestionService(store, parser).ingest_payloads(
            DatasetManifest(
                tenant_id=TENANT, dataset_id="auth", dataset_version="1", batch_id="auth",
                source_system="reference", connector_version="1", parser_name=parser.name,
                parser_version=parser.version,
            ),
            [{"event_id": "login-1", "event_type": "login_event", "domain": "authentication",
              "source_system": "edr-auth", "observed_at": NOW.isoformat(), "host_id": "host-1",
              "data": {"user": "root", "result": "success", "service": "sshd",
                       "source_ip": "192.0.2.1"}}],
            ingested_at=NOW,
        )
        gateway = InvestigationToolGateway(
            SituationalAwarenessDataAdapter(SQLiteInvestigationDataAdapter(store)),
            SingleHostBoundaryPolicy(tenant_id=TENANT, case_id="case-a", run_id="run-a"),
        )
        result = gateway.invoke(
            "query_authentication_activities", {"results": ["success"]},
            ToolRuntimeContext(tenant_id=TENANT, case_id="case-a", run_id="run-a", scope=_context().scope),
            InvestigationToolLedger(),
        )
        assert len(result.activities) == 1
        assert result.activities[0].activity_type == "authentication"
        assert result.activities[0].user_ref == "user:root"
    finally:
        store.close()


def test_replacing_context_source_does_not_change_the_contract():
    def database(query):
        return QueryPage(records=[_alert()])

    def ir(query):
        # The source-specific mapping produces the same standard record.
        row = {"id": "alert-1", "host": "host-1", "hash": "a" * 64}
        return QueryPage(records=[_alert(source_record_id=row["id"], host_ref=row["host"],
                                        file_hash=FileHash(algorithm="sha256", digest=row["hash"]))])

    first = SituationalAwarenessDataAdapter(alerts=database).query_alerts(_query())
    second = SituationalAwarenessDataAdapter(alerts=ir).query_alerts(_query())
    # created_at is query/serialization metadata, not source event identity.
    assert first.model_dump(exclude={"records": {"__all__": {"created_at"}}}) == second.model_dump(
        exclude={"records": {"__all__": {"created_at"}}}
    )


def test_empty_results_are_distinct_from_unsupported_and_failed_queries():
    empty = SituationalAwarenessDataAdapter(alerts=lambda query: QueryPage[UnknownFileAlert]())
    assert empty.query_alerts(_query()).records == []
    with pytest.raises(UnsupportedDataQuery, match="query_alerts"):
        SituationalAwarenessDataAdapter().query_alerts(_query())

    error = TimeoutError("source connection details")

    def failed(query):
        raise error

    with pytest.raises(DataQueryFailed) as failure:
        SituationalAwarenessDataAdapter(alerts=failed).query_alerts(_query())
    assert failure.value.__cause__ is error
    assert "source connection details" not in str(failure.value)


def test_composite_handler_failure_does_not_become_a_partial_result():
    def composite(query):
        first_source = [_alert()]
        assert first_source
        raise ConnectionError("second source failed")

    with pytest.raises(DataQueryFailed):
        SituationalAwarenessDataAdapter(alerts=composite).query_alerts(_query())


def test_source_access_errors_are_preserved():
    error = DataAccessError("outside the source scope")

    def denied(query):
        raise error

    with pytest.raises(DataAccessError) as failure:
        SituationalAwarenessDataAdapter(alerts=denied).query_alerts(_query())
    assert failure.value is error


@pytest.mark.parametrize("overrides", [{"host_ref": "host-2"}, {"tenant_id": "tenant-b"}])
def test_new_queries_reject_out_of_scope_source_records(overrides):
    data = SituationalAwarenessDataAdapter(alerts=lambda query: QueryPage(records=[_alert(**overrides)]))
    with pytest.raises(DataAccessError):
        data.query_alerts(_query())


def test_asset_scope_is_checked_before_read_and_results_are_not_fabricated():
    calls = []

    def asset(context, host_ref):
        calls.append(host_ref)
        return None

    data = SituationalAwarenessDataAdapter(asset_info=asset)
    with pytest.raises(DataAccessError):
        data.get_asset_info(_context(), "host-2")
    assert calls == []
    assert data.get_asset_info(_context(), "host-1") is None
    assert calls == ["host-1"]


def test_asset_and_source_assessment_keep_source_semantics():
    asset = AssetInfo(tenant_id=TENANT, source_system="cmdb", host_ref="host-1",
                      attributes={"role": "payments"})
    assessment = SourceAssessment(
        tenant_id=TENANT, source_system="siem-ir", source_record_id="assessment-1",
        host_ref="host-1", entity_refs=["file:a"], method="model", conclusion="suspicious", score=20,
    )
    data = SituationalAwarenessDataAdapter(
        asset_info=lambda context, host_ref: asset,
        source_assessments=lambda query: QueryPage(records=[assessment]),
    )
    assert data.get_asset_info(_context(), "host-1") is asset
    result = data.query_source_assessments(_query(AssessmentQuery, entity_refs=["file:a"]))
    assert result.records[0].conclusion == "suspicious"
    assert result.records[0].method == "model"
    assert "verdict" not in result.records[0].model_dump()
    assert "operation" not in asset.model_dump()


def test_reputation_cannot_return_a_different_file_hash():
    data = SituationalAwarenessDataAdapter(file_reputation=lambda context, file_hash: FileReputation(
        tenant_id=TENANT, source_system="ir", file_hash=FileHash(algorithm="md5", digest="a" * 32),
        queried_lists=["baseline"], queried_at=NOW,
    ))
    with pytest.raises(DataAccessError, match="hash"):
        data.query_file_reputation(_context(), FILE_HASH)


@pytest.mark.parametrize("digest", ["a" * 32, "z" * 64])
def test_hash_algorithm_and_digest_must_agree(digest):
    with pytest.raises(ValidationError):
        FileHash(algorithm="sha256", digest=digest)
    assert FileHash(algorithm="SHA256", digest="A" * 64) == FILE_HASH


def test_reputation_cannot_claim_a_match_in_an_unqueried_list():
    with pytest.raises(ValidationError):
        FileReputation(
            tenant_id=TENANT, source_system="ir", file_hash=FILE_HASH, queried_lists=["baseline"],
            matches=[ReputationMatch(list_name="blocklist")], queried_at=NOW,
        )


def test_query_validates_scope_and_page_size():
    with pytest.raises(ValidationError):
        AlertQuery(tenant_id=TENANT, scope=Scope(host_ids=[]))
    with pytest.raises(ValidationError):
        _query(limit=0)
    with pytest.raises(ValidationError):
        _query(scope=Scope(host_ids=["host-1"], start_time=NOW, end_time=NOW.replace(hour=0)))


def test_unsupported_activity_method_is_explicit():
    data = SituationalAwarenessDataAdapter()
    with pytest.raises(UnsupportedDataQuery, match="query_socket"):
        data.query_socket(None)
    with pytest.raises(UnsupportedDataQuery, match="get_raw_record"):
        data.get_raw_record(TENANT, "activity-1")
