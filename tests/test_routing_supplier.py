"""Feature 18 unit gates: category routing, per-supplier failure isolation
and catalog merging of the RoutingSupplier composition."""

from __future__ import annotations

from threat_agent.knowledge.adapters.routing import RoutingSupplier
from threat_agent.knowledge.ports.supplier_retrieval import (
    SupplierItem,
    SupplierRetrievalPort,
    SupplierRetrievalRequest,
    SupplierSourceOutcome,
    SupplierSourceQuery,
)


def _item(knowledge_id: str) -> SupplierItem:
    return SupplierItem(
        knowledge_id=knowledge_id,
        version="1",
        chunk_id="c1",
        title=knowledge_id,
        summary="s",
        content="c",
        source_uri="internal://test",
        relevance="medium",
    )


class RecordingSupplier(SupplierRetrievalPort):
    """Scripted supplier: returns canned outcomes, remembers its requests."""

    def __init__(self, supplier_id: str, *, outcomes=None, raise_error=False, wrong_arity=False, catalog=None):
        self.supplier_id = supplier_id
        self.outcomes = outcomes or {}
        self.raise_error = raise_error
        self.wrong_arity = wrong_arity
        self.catalog_value = catalog
        self.requests: list[list[str]] = []

    def retrieve_sources(self, request):
        if self.raise_error:
            raise RuntimeError(f"{self.supplier_id} is down")
        self.requests.append([query.source_category for query in request.sources])
        outcomes = [self.outcomes[query.source_category] for query in request.sources]
        return outcomes[:-1] if self.wrong_arity else outcomes

    def catalog(self):
        return self.catalog_value


def _outcome(category: str, status: str = "available", *, items=1) -> SupplierSourceOutcome:
    return SupplierSourceOutcome(
        source_category=category,
        status=status,
        items=[_item(f"{category}-{index}") for index in range(items)],
        diagnostics={},
    )


def _request(*categories: str) -> SupplierRetrievalRequest:
    return SupplierRetrievalRequest(
        query_id="kquery-test",
        tenant_id="tenant-a",
        case_id="case-1",
        actor_id="actor-1",
        timeout_seconds=10.0,
        sources=[
            SupplierSourceQuery(source_category=category, query_text="q")
            for category in categories
        ],
    )


def test_routes_each_source_to_its_owning_supplier():
    attack = RecordingSupplier(
        "attack",
        outcomes={
            "attack_technique": _outcome("attack_technique"),
            # never asked for these — routing owns the mapping:
            "org_sop": _outcome("org_sop"),
        },
    )
    default = RecordingSupplier(
        "reference",
        outcomes={
            "attack_technique": _outcome("attack_technique"),
            "analyst_judgment_experience": _outcome("analyst_judgment_experience"),
            "org_sop": _outcome("org_sop"),
        },
    )
    router = RoutingSupplier(routes={"attack_technique": attack}, default=default)

    outcomes = router.retrieve_sources(
        _request("analyst_judgment_experience", "attack_technique", "org_sop")
    )

    # The attack supplier sees exactly its routed category; the default keeps
    # the rest, and the response preserves the original source order.
    assert attack.requests == [["attack_technique"]]
    assert default.requests == [["analyst_judgment_experience", "org_sop"]]
    assert [outcome.source_category for outcome in outcomes] == [
        "analyst_judgment_experience",
        "attack_technique",
        "org_sop",
    ]
    assert [item.knowledge_id for item in outcomes[1].items] == ["attack_technique-0"]


def test_supplier_failure_isolates_to_its_own_categories():
    attack = RecordingSupplier("attack", raise_error=True)
    default = RecordingSupplier(
        "reference",
        outcomes={
            "analyst_judgment_experience": _outcome("analyst_judgment_experience"),
            "attack_technique": _outcome("attack_technique"),
        },
    )
    router = RoutingSupplier(routes={"attack_technique": attack}, default=default)

    outcomes = router.retrieve_sources(
        _request("attack_technique", "analyst_judgment_experience")
    )

    assert outcomes[0].status == "error"
    assert "供应商异常" in outcomes[0].limitations[0]
    assert outcomes[1].status == "available"


def test_arity_violation_becomes_error_not_silent_loss():
    attack = RecordingSupplier(
        "attack",
        outcomes={"attack_technique": _outcome("attack_technique")},
        wrong_arity=True,
    )
    router = RoutingSupplier(routes={"attack_technique": attack}, default=attack)

    outcomes = router.retrieve_sources(_request("attack_technique"))

    assert outcomes[0].status == "error"
    assert "不一致" in outcomes[0].limitations[0]


def test_catalog_merges_with_routed_categories_taking_precedence():
    attack = RecordingSupplier(
        "attack",
        catalog={
            "supplier_id": "attack",
            "categories": [
                {"category": "attack_technique", "items": [{"knowledge_id": "T1053"}]}
            ],
        },
    )
    default = RecordingSupplier(
        "reference",
        catalog={
            "supplier_id": "reference",
            "categories": [
                {"category": "attack_technique", "items": [{"knowledge_id": "stale"}]},
                {"category": "org_sop", "items": [{"knowledge_id": "ke-sop-1"}]},
            ],
        },
    )
    router = RoutingSupplier(routes={"attack_technique": attack}, default=default)

    catalog = router.catalog()
    by_category = {
        category["category"]: category for category in catalog["categories"]
    }
    assert set(by_category) == {"attack_technique", "org_sop"}
    assert by_category["attack_technique"]["items"] == [{"knowledge_id": "T1053"}]
    assert by_category["org_sop"]["items"] == [{"knowledge_id": "ke-sop-1"}]


def test_catalog_survives_one_supplier_catalog_failure():
    attack = RecordingSupplier("attack", catalog=None)  # catalog() returns None
    default = RecordingSupplier(
        "reference",
        catalog={
            "supplier_id": "reference",
            "categories": [{"category": "org_sop", "items": []}],
        },
    )
    router = RoutingSupplier(routes={"attack_technique": attack}, default=default)

    catalog = router.catalog()
    assert [category["category"] for category in catalog["categories"]] == ["org_sop"]


def test_all_catalogs_failing_degrades_to_none():
    broken = RecordingSupplier("broken", catalog=None)
    router = RoutingSupplier(routes={}, default=broken)
    assert router.catalog() is None
