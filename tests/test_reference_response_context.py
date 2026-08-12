from threat_agent.contracts import (
    CandidateVerdict,
    DataProfile,
    Fact,
    JudgmentResult,
    ReferenceAsset,
    VerdictLevel,
)
from threat_agent.data_foundation.adapters import SQLiteReferenceDataStore
from threat_agent.response_advisory.adapters import ReferenceResponseContextAdapter
from threat_agent.response_advisory.application.planner import DeterministicResponsePlanner


def _judgment() -> JudgmentResult:
    return JudgmentResult(
        tenant_id="demo",
        case_id="case-one",
        source_identity="test",
        verdict=CandidateVerdict(
            level=VerdictLevel.CONFIRMED_MALICIOUS,
            threat_type="backdoor_c2",
            summary="Confirmed for context comparison",
            supporting_refs=["fact-one"],
        ),
        facts=[
            Fact(
                fact_id="fact-one",
                fact_type="execution",
                statement="The process executed",
                subject_refs=["host:host-1"],
                evidence_refs=["ev-one"],
                verification_method="test",
            )
        ],
        evidence_refs=["ev-one"],
    )


def _profile() -> DataProfile:
    return DataProfile(
        profile_id="l3",
        dataset_version="v1",
        level="l3",
        asset_context_visible=True,
        description="Asset-aware profile",
    )


def test_same_judgment_gets_asset_specific_response_constraints(tmp_path):
    store = SQLiteReferenceDataStore(tmp_path / "reference.sqlite")
    assets = {
        "production": ReferenceAsset(
            host_id="host-1", asset_name="payments", environment="production",
            business_system="payments", criticality="critical", business_owner="payments",
            security_owner="soc", maintenance_window="Sunday", isolation_policy="dual_approval",
            isolation_impact="Payment traffic stops",
        ),
        "test": ReferenceAsset(
            host_id="host-1", asset_name="sandbox", environment="test",
            business_system="lab", criticality="low", business_owner="engineering",
            security_owner="soc", maintenance_window="any time", isolation_policy="allowed",
            isolation_impact="No production impact",
        ),
    }
    judgment = _judgment()
    judgment_before = judgment.model_dump_json()
    plans = {}
    for dataset_id, asset in assets.items():
        store.put_asset(dataset_id, "v1", asset)
        context = ReferenceResponseContextAdapter(
            store, dataset_id=dataset_id, dataset_version="v1", profile=_profile()
        ).load(judgment)
        plans[dataset_id] = DeterministicResponsePlanner().propose(judgment, [], [], context)
    production_action = plans["production"].actions[0]
    test_action = plans["test"].actions[0]
    assert production_action.approval_class == "business_owner"
    assert test_action.approval_class == "security_lead"
    assert production_action.expected_impact != test_action.expected_impact
    assert judgment.model_dump_json() == judgment_before
