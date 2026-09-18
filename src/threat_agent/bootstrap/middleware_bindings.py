"""Feature 15 step 02 — compose the reusable BoundaryMiddleware with the
business investigation boundary.

This module is the composition root adapter: it touches both case_management
(the typed single-host policy) and judgment (the gateway), so it lives in
bootstrap by the dependency rules enforced in test_architecture_dependencies.

Division of labor:

- The typed ``SingleHostBoundaryPolicy`` stays the single authorization
  truth. ``SingleHostToolBoundary.authorize`` delegates to it and translates
  business denials into the middleware's structured rejection.
- Typed result validation and ledger recording stay inside the gateway
  (defense in depth). ``validate`` mirrors the two result-level guarantees —
  run identity and alert-host containment — at the serialized ToolMessage
  level; full typed checks remain gateway-side.
- ``investigation_gateway_tools`` builds executing langchain tools with the
  same model-facing catalog the planner registers, each delegating to
  ``InvestigationToolGateway.invoke`` with server-side identity.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from langchain_core.messages import ToolMessage
from langchain_core.tools import StructuredTool

from ..agent_middleware import (
    BudgetExhausted,
    BudgetMiddleware,
    BoundaryMiddleware,
    BoundaryRejection,
    BoundaryViolationError as MiddlewareViolation,
    LimitsBudgetPolicy,
    Reducer,
    ReducerMiddleware,
)
from ..case_management import SingleHostBoundaryPolicy
from ..data_foundation.ports.evidence_query import DataAccessError
from ..contracts import InvestigationToolLedger, ToolRuntimeContext
from ..judgment import (
    BoundaryViolationError as BusinessViolation,
    InvestigationToolGateway,
)
from ..judgment.application.data_tool_planner import TOOL_DEFINITIONS
from ..judgment.application.tool_observation import brief_result
from ..judgment.domain.models import Budget


class SingleHostToolBoundary:
    """Adapt the typed single-host policy to the ToolBoundary protocol."""

    def __init__(
        self,
        policy: SingleHostBoundaryPolicy,
        context: ToolRuntimeContext,
        ledger: InvestigationToolLedger,
    ):
        self.policy = policy
        self.context = context
        self.ledger = ledger

    def authorize(self, tool_name: str, arguments, dict_ledger: dict) -> None:
        # Keep a reference in the middleware ledger so checkpointed runs can
        # recover the typed ledger object.
        dict_ledger.setdefault("investigation_ledger", self.ledger)
        try:
            self.policy.authorize_call(
                self.context, self.ledger, tool_name, dict(arguments)
            )
        except BusinessViolation as violation:
            denial = violation.denial
            raise MiddlewareViolation(
                BoundaryRejection(
                    code=denial.code,
                    tool_name=tool_name,
                    message=denial.message,
                    resource_refs=[*denial.host_refs, *denial.reference_ids],
                )
            ) from violation

    def validate(self, tool_name: str, message: ToolMessage, dict_ledger: dict) -> ToolMessage:
        payload = _json_payload(message)
        if payload is not None:
            self._check_identity(tool_name, payload)
            self._check_hosts(tool_name, payload)
        return message

    def _check_identity(self, tool_name: str, payload: dict[str, Any]) -> None:
        if not {"tenant_id", "case_id", "run_id"} <= payload.keys():
            return
        actual = (payload["tenant_id"], payload["case_id"], payload["run_id"])
        expected = (self.context.tenant_id, self.context.case_id, self.context.run_id)
        if actual != expected:
            # Identity mismatch is a wiring bug, mirroring the typed policy.
            raise ValueError(
                f"Query result identity does not match the run context for tool {tool_name}"
            )

    def _check_hosts(self, tool_name: str, payload: dict[str, Any]) -> None:
        hosts = set(self.context.scope.host_ids)
        activities = payload.get("activities")
        if not isinstance(activities, list):
            timeline = payload.get("timeline")
            activities = timeline if isinstance(timeline, list) else []
        for activity in activities:
            if not isinstance(activity, dict):
                continue
            host = activity.get("host_ref")
            if host is not None and host not in hosts:
                raise MiddlewareViolation(
                    BoundaryRejection(
                        code="host_out_of_scope",
                        tool_name=tool_name,
                        message="工具结果包含授权主机之外的活动",
                        resource_refs=[str(host)],
                    )
                )


def _json_payload(message: ToolMessage) -> dict[str, Any] | None:
    if not isinstance(message.content, str):
        return None
    try:
        payload = json.loads(message.content)
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def investigation_gateway_tools(
    gateway: InvestigationToolGateway,
    context: ToolRuntimeContext,
    ledger: InvestigationToolLedger,
) -> list[StructuredTool]:
    """Executing tools over the gateway, sharing the planner's tool catalog."""

    def build(name: str, schema: type, description: str) -> StructuredTool:
        def execute(**arguments: Any) -> dict:
            # Domain-level tool failures (unknown refs, invalid arguments) are
            # returned to the model as observable errors so it can self-correct;
            # only truly unexpected bugs propagate and fail the run.
            try:
                result = gateway.invoke(name, dict(arguments), context, ledger)
            except (DataAccessError, ValueError, KeyError) as error:
                return {
                    "error": "tool_input_rejected",
                    "error_type": type(error).__name__,
                    "message": str(error),
                }
            return result.model_dump(mode="json")

        return StructuredTool.from_function(
            func=execute,
            name=name,
            description=description,
            args_schema=schema,
        )

    return [
        build(name, schema, description)
        for name, schema, description in TOOL_DEFINITIONS
        if name != "finish_investigation"
    ]


def boundary_middleware_for(
    policy: SingleHostBoundaryPolicy,
    context: ToolRuntimeContext,
    ledger: InvestigationToolLedger,
    *,
    on_event: Callable | None = None,
) -> BoundaryMiddleware:
    """Convenience constructor used by the dual-run harness and future wiring."""
    return BoundaryMiddleware(
        SingleHostToolBoundary(policy, context, ledger), on_event=on_event
    )


def budget_middleware_for(
    case_budget: Budget,
    *,
    max_total_tokens: int | None = None,
    on_event: Callable | None = None,
) -> BudgetMiddleware:
    """Map the investigation Budget onto the middleware budget policy.

    ``max_iterations`` counts model-driven planning rounds and maps to the
    model-call budget; ``max_tool_calls`` maps one-to-one. The
    report-rejudgment dimension belongs to the report pipeline and is
    deliberately not mapped.
    """
    return BudgetMiddleware(
        LimitsBudgetPolicy(
            max_model_calls=case_budget.max_iterations,
            max_tool_calls=case_budget.max_tool_calls,
            max_total_tokens=max_total_tokens,
        ),
        on_event=on_event,
    )


def run_with_budget_degradation(agent, payload, *, on_exhausted, config=None):
    """Invoke an agent, routing the budget stop signal to a degradation path.

    Returns ``(result, None)`` on normal completion, or ``(None, degraded)``
    where ``degraded`` is whatever ``on_exhausted(exhausted)`` produced. The
    business degradation path reads its own ledger/state objects, which the
    bindings hold by reference.
    """
    try:
        return agent.invoke(payload, config=config), None
    except BudgetExhausted as exhausted:
        return None, on_exhausted(exhausted)


class BriefToolResultReducer:
    """Domain-aware tool-result downsizing reusing the investigation field
    projection from ``brief_result`` (salient fields per activity, bounded
    activity lists)."""

    def reduce(self, tool_name: str, result) -> dict:
        if not isinstance(result, dict):
            return result
        return brief_result(result)


def brief_reducer_middleware(
    *,
    reducer: Reducer | None = None,
    on_event: Callable | None = None,
) -> ReducerMiddleware:
    """ReducerMiddleware wired with the investigation field projection."""
    return ReducerMiddleware(reducer or BriefToolResultReducer(), on_event=on_event)
