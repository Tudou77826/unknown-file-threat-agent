"""Framework execution context: authorization is bound once, inherited全程.

Tenant, case and caller identity travel in a contextvar, never as business
parameters. The binding happens at the framework orchestration entry (see the
architecture tests); every layer below reads it, business code cannot fill or
tamper with authorization fields.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True)
class ExecutionContext:
    """一次运行的身份事实：租户、案件、调用身份与运行标识。"""

    tenant_id: str
    case_id: str
    actor_id: str
    run_id: str | None = None


_CURRENT: ContextVar[ExecutionContext | None] = ContextVar(
    "threat_agent_execution_context", default=None
)


@contextmanager
def bind_execution_context(context: ExecutionContext):
    """Bind the run identity for the enclosed call chain.

    Only the framework orchestration entry (bootstrap / case graph) may call
    this; the architecture tests enforce that business modules never bind.
    """

    token = _CURRENT.set(context)
    try:
        yield
    finally:
        _CURRENT.reset(token)


def current_execution_context() -> ExecutionContext:
    context = _CURRENT.get()
    if context is None:
        raise RuntimeError(
            "No execution context is bound on this call chain; "
            "the framework entry must bind tenant/case/actor identity once"
        )
    return context


def try_current_execution_context() -> ExecutionContext | None:
    return _CURRENT.get()
